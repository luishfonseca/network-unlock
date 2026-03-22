package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
)

func Register(from net.IP, addr string, fingerprint [32]byte, secret []byte) ([]byte, error) {
	secretBuf := bytes.NewBuffer(bytes.Clone(secret))
	fp := hex.EncodeToString(fingerprint[:])

	resp, err := (&http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: from},
			}).DialContext,
		},
	}).Post(fmt.Sprintf("http://%s/register/%s", addr, fp), "application/octet-stream", secretBuf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
