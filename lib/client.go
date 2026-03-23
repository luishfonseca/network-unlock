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

func Register(ctx context.Context, from net.IP, addr string, fingerprint [32]byte, secret []byte) (body []byte, err error) {
	secretBuf := bytes.NewBuffer(bytes.Clone(secret))
	fp := hex.EncodeToString(fingerprint[:])

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: from},
	}

	if _, ok := ctx.Deadline(); ok {
		dialer.Deadline, _ = ctx.Deadline()
	}

	var resp *http.Response
	if resp, err = (&http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
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

func Unlock(ctx context.Context, from net.IP, addr string, cert, key, peer []byte) (body []byte, err error) {
	var tlsCert tls.Certificate
	if tlsCert, err = tls.X509KeyPair(cert, key); err != nil {
		return
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(peer) {
		return nil, fmt.Errorf("failed to append peer certificate to CA pool")
	}

	dialer := &net.Dialer{}
	if from != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: from}
	}

	if _, ok := ctx.Deadline(); ok {
		dialer.Deadline, _ = ctx.Deadline()
	}

	var resp *http.Response
	if resp, err = (&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{tlsCert},
				ClientAuth:   tls.RequireAnyClientCert,
				MinVersion:   tls.VersionTLS13,
			},
			DialContext: dialer.DialContext,
		},
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
