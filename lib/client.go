package lib

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
)

func Register(ctx context.Context, from net.IP, addr string, fingerprint [32]byte, secret []byte) ([]byte, error) {
	secretBuf := bytes.NewBuffer(bytes.Clone(secret))
	fp := hex.EncodeToString(fingerprint[:])

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: from},
	}

	if _, ok := ctx.Deadline(); ok {
		dialer.Deadline, _ = ctx.Deadline()
	}

	resp, err := (&http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}).Post(fmt.Sprintf("http://%s/register/%s", addr, fp), "application/octet-stream", secretBuf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("register: %s", resp.Status)
	}

	return body, nil
}

func Unlock(ctx context.Context, from net.IP, addr string, cert, key, peer []byte) ([]byte, error) {
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(peer) {
		return nil, fmt.Errorf("append peer certificate to CA pool")
	}

	dialer := &net.Dialer{}
	if from != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: from}
	}

	if _, ok := ctx.Deadline(); ok {
		dialer.Deadline, _ = ctx.Deadline()
	}

	resp, err := (&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{tlsCert},
				MinVersion:   tls.VersionTLS13,
			},
			DialContext: dialer.DialContext,
		},
	}).Get(fmt.Sprintf("https://%s/unlock", addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	return body, nil
}
