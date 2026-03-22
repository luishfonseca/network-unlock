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
	"time"
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

func ServeRegister(ctx context.Context, cert tls.Certificate, addr string) error {
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
			log.Printf("register: %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		secret, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("register: %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mu.Lock()
		stored[Fingerprint(fp)] = &Entry{
			secret,
			remote,
			time.Now(),
		}
		mu.Unlock()

		var certPem []byte
		if certPem, err = EncodeCertificate(cert.Certificate[0]); err != nil {
			return
		}

		log.Printf("register: remote=%s fingerprint=%x", r.RemoteAddr, fp)
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err = w.Write(certPem); err != nil {
			log.Printf("register: %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	return http.ListenAndServe(addr, mux)
}

func ServeUnlock(ctx context.Context, ttl time.Duration, cert tls.Certificate, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/unlock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		fp := sha256.Sum256(cert.Raw)

		mu.Lock()
		entry, found := stored[fp]
		if found && time.Since(entry.when) > ttl {
			delete(stored, fp)
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
			log.Printf("unlock: %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		remoteAddrs := []net.IP{remote, entry.remote}
		certAddrs := slices.Clone(cert.IPAddresses)
		if !equalAddrs(remoteAddrs, certAddrs) {
			log.Printf("unlock: rejected, IP mismatch: remote=%v cert=%v", remoteAddrs, certAddrs)
			http.Error(w, "IP mismatch", http.StatusForbidden)
			return
		}

		mu.Lock()
		delete(stored, fp)
		mu.Unlock()

		log.Printf("unlock: remote=%s fingerprint=%x", r.RemoteAddr, fp)
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err = w.Write(entry.secret); err != nil {
			log.Printf("register: %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	return (&http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS13,
		},
	}).ListenAndServeTLS("", "")
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

func parseIP(addr string) (ip net.IP, err error) {
	if addr, _, err = net.SplitHostPort(addr); err != nil {
		return
	}

	if ip = net.ParseIP(addr); ip == nil {
		return nil, fmt.Errorf("Failed to parse %s", addr)
	}

	return
}

func equalAddrs(remoteAddrs []net.IP, certAddrs []net.IP) bool {
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
