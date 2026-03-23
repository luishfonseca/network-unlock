package lib

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
func GenerateCertificate(cn string, ips []net.IP) (tls.Certificate, error) {
	serial, err := generateRandomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}

	info := &x509.Certificate{
		SerialNumber:          &serial,
		Subject:               pkix.Name{CommonName: cn},
		IPAddresses:           ips,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, info, info, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPem, err := EncodeCertificate(cert)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPem, err := EncodeKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPem, keyPem)
}

func EncodeCertificate(cert []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func EncodeKey(key crypto.PrivateKey) ([]byte, error) {
	key, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDH private key")
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func generateRandomSerial() (big.Int, error) {
	var serial big.Int
	bytes := make([]byte, 20)
	_, err := rand.Read(bytes)
	if err != nil {
		return serial, err
	}

	serial.SetBytes(bytes)
	serial = *serial.Rsh(&serial, 1)
	return serial, nil
}
