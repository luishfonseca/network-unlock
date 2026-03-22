package lib

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
)

func Register(from net.IP, addr string, fingerprint [32]byte, secret []byte) (body []byte, err error) {
	secretBuf := bytes.NewBuffer(bytes.Clone(secret))
	fp := hex.EncodeToString(fingerprint[:])

	var resp *http.Response
	if resp, err = (&http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: from},
			}).DialContext,
		},
	}).Post(fmt.Sprintf("http://%s/register/%s", addr, fp), "application/octet-stream", secretBuf); err != nil {
		return
	}
	defer resp.Body.Close()

	if body, err = io.ReadAll(resp.Body); err != nil {
		return
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	return
}

func Unlock(from net.IP, addr string, cert, key, peer []byte) (body []byte, err error) {
	var tlsCert tls.Certificate
	if tlsCert, err = tls.X509KeyPair(cert, key); err != nil {
		return
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(peer) {
		return nil, fmt.Errorf("failed to append peer certificate to CA pool")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{tlsCert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS13,
		},
	}

	if from != nil {
		transport.DialContext = (&net.Dialer{
			LocalAddr: &net.TCPAddr{IP: from},
		}).DialContext
	}

	var resp *http.Response
	if resp, err = (&http.Client{
		Transport: transport,
	}).Get(fmt.Sprintf("https://%s/unlock", addr)); err != nil {
		return
	}
	defer resp.Body.Close()

	if body, err = io.ReadAll(resp.Body); err != nil {
		return
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	return
}
