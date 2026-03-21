package lib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
func GenerateCertificate(cn string, ip string) (tlsCert tls.Certificate, err error) {
	var serial big.Int
	if serial, err = generateRandomSerial(); err != nil {
		return
	}

	info := &x509.Certificate{
		SerialNumber:          &serial,
		Subject:               pkix.Name{CommonName: cn},
		IPAddresses:           []net.IP{net.ParseIP(ip)},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	var key *ecdsa.PrivateKey
	if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return
	}

	var keyBytes []byte
	if keyBytes, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		return
	}

	var cert []byte
	if cert, err = x509.CreateCertificate(rand.Reader, info, info, &key.PublicKey, key); err != nil {
		return
	}

	certBuffer := new(bytes.Buffer)
	if err = pem.Encode(certBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		return
	}

	keyBuffer := new(bytes.Buffer)
	if err = pem.Encode(keyBuffer, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return
	}

	return tls.X509KeyPair(certBuffer.Bytes(), keyBuffer.Bytes())
}

func generateRandomSerial() (serial big.Int, err error) {
	bytes := make([]byte, 20)
	if _, err = rand.Read(bytes); err != nil {
		return
	}
	serial.SetBytes(bytes)
	serial = *serial.Rsh(&serial, 1)
	return
}
