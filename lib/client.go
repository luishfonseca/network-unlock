package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

func Register(addr string, fingerprint [32]byte, secret []byte) ([]byte, error) {
	secretBuf := bytes.NewBuffer(bytes.Clone(secret))
	fp := hex.EncodeToString(fingerprint[:])

	resp, err := http.Post(fmt.Sprintf("http://%s/register/%s", addr, fp), "application/octet-stream", secretBuf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
