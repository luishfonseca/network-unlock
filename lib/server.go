package lib

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Fingerprint [32]byte

type Entry struct {
	secret []byte
	remote net.IP
	when   time.Time
}

var (
	mu     sync.Mutex
	stored map[Fingerprint]*Entry = map[Fingerprint]*Entry{}
)

// ServeRegister runs on the trusted internal network over plain HTTP.
// Clients deposit their secret share here before rebooting; the server
// returns its own certificate so the client can pin it for the mTLS unlock.
func ServeRegister(ctx context.Context, cert tls.Certificate, addr string, v6 bool) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/register/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			log.Printf("register: method not allowed: %s", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		arg := strings.TrimPrefix(r.URL.Path, "/register/")
		fp, err := hex.DecodeString(arg)
		if err != nil || len(fp) != 32 {
			log.Printf("register: bad fingerprint: %s", arg)
			http.Error(w, "bad fingerprint", http.StatusBadRequest)
			return
		}

		remote, err := parseIP(r.RemoteAddr)
		if err != nil {
			log.Printf("register: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		secret, err := io.ReadAll(io.LimitReader(r.Body, 1024))
		if err != nil {
			log.Printf("register: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Reject duplicates: each fingerprint is single-use, so a second
		// registration with the same fingerprint means something is wrong.
		mu.Lock()
		if _, exists := stored[Fingerprint(fp)]; exists {
			mu.Unlock()
			log.Printf("register: rejected duplicate fingerprint: %x", fp)
			http.Error(w, "duplicate registration", http.StatusConflict)
			return
		}
		stored[Fingerprint(fp)] = &Entry{
			secret,
			remote,
			time.Now(),
		}
		mu.Unlock()

		certPem, err := EncodeCertificate(cert.Certificate[0])
		if err != nil {
			log.Printf("register: encode certificate: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		log.Printf("register: remote=%s fingerprint=%x", r.RemoteAddr, fp)
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := w.Write(certPem); err != nil {
			log.Printf("register: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	ln, err := listen(ctx, addr, v6)
	if err != nil {
		return err
	}

	return http.Serve(ln, mux)
}

// ServeUnlock runs on the external/public network over mTLS.
// The client authenticates with the ephemeral cert it generated during prepare;
// the server identifies it by the cert's fingerprint and returns the stored share.
func ServeUnlock(ctx context.Context, ttl time.Duration, cert tls.Certificate, addr string, v6 bool) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/unlock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fp := sha256.Sum256(cert.Raw)

		// Delete-on-read: each share can only be retrieved once.
		// This limits the window for replay if the TLS session is somehow compromised.
		mu.Lock()
		entry, found := stored[fp]
		if found {
			delete(stored, fp)
		}
		if time.Since(entry.when) > ttl {
			found = false
		}
		mu.Unlock()

		if !found {
			log.Printf("unlock: rejected, no entry for %x", fp)
			http.Error(w, "no entry found", http.StatusForbidden)
			return
		}

		remote, err := parseIP(r.RemoteAddr)
		if err != nil {
			log.Printf("unlock: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// The client's cert was issued with its internal + public IPs as SANs.
		// Verify that the IPs the server has actually seen (registration source
		// and current connection source) match those claimed SANs -- this binds
		// the cert to the network identity observed by the server on both networks.
		remoteAddrs := []net.IP{remote, entry.remote}
		certAddrs := slices.Clone(cert.IPAddresses)
		if !equalAddrs(remoteAddrs, certAddrs) {
			log.Printf("unlock: rejected, IP mismatch: remote=%v cert=%v", remoteAddrs, certAddrs)
			http.Error(w, "IP mismatch", http.StatusForbidden)
			return
		}

		log.Printf("unlock: remote=%s fingerprint=%x", r.RemoteAddr, fp)
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := w.Write(entry.secret); err != nil {
			log.Printf("unlock: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	ln, err := listen(ctx, addr, v6)
	if err != nil {
		return err
	}

	return (&http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// RequireAnyClientCert, not RequireAndVerify -- the client certs are
			// self-signed, so there's no CA to verify against. Authentication is
			// done by matching the cert fingerprint to a registered entry instead.
			ClientAuth: tls.RequireAnyClientCert,
			MinVersion: tls.VersionTLS13,
		},
	}).ServeTLS(ln, "", "")
}

func CleanupEntries(ttl time.Duration) int {
	count := 0

	mu.Lock()
	for fp, entry := range stored {
		if time.Since(entry.when) > ttl {
			delete(stored, fp)
			count++
		}
	}
	mu.Unlock()

	return count
}

// listen creates a TCP listener with IP_FREEBIND / IPV6_FREEBIND so the server
// can bind to an address before the interface is fully configured. This lets the
// service start early at boot, even before the network stack has assigned IPs.
func listen(ctx context.Context, addr string, v6 bool) (net.Listener, error) {
	var network string
	if v6 {
		network = "tcp6"
	} else {
		network = "tcp"
	}

	return (&net.ListenConfig{
		// https://systemd.io/NETWORK_ONLINE/
		// https://iximiuz.com/en/posts/go-net-http-setsockopt-example/
		Control: func(network, addr string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				if v6 {
					operr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
				} else {
					operr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
				}
			}); err != nil {
				return err
			}
			return operr
		},
	}).Listen(ctx, network, addr)
}

func parseIP(addr string) (net.IP, error) {
	addr, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("parse ip %s", addr)
	}

	return ip, nil
}

func normalizeIPs(addrs []net.IP) []net.IP {
	out := make([]net.IP, len(addrs))
	for i, ip := range addrs {
		out[i] = ip.To16()
	}
	return out
}

func equalAddrs(remoteAddrs []net.IP, certAddrs []net.IP) bool {
	remoteAddrs = normalizeIPs(remoteAddrs)
	certAddrs = normalizeIPs(certAddrs)

	slices.SortFunc(remoteAddrs, func(i, j net.IP) int {
		return bytes.Compare(i, j)
	})

	slices.SortFunc(certAddrs, func(i, j net.IP) int {
		return bytes.Compare(i, j)
	})

	return slices.EqualFunc(remoteAddrs, certAddrs, func(i, j net.IP) bool {
		return i.Equal(j)
	})
}
