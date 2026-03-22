package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Prepare(ctx context.Context, cmd *cli.Command) (err error) {
	log.Printf("Generating ephemeral certificate")

	var cert tls.Certificate
	if cert, err = lib.GenerateCertificate("network-unlock-client", []net.IP{
		cmdIP(cmd, "self-internal"),
		cmdIP(cmd, "self-public"),
	}); err != nil {
		return err
	}

	var certPem []byte
	if certPem, err = lib.EncodeCertificate(cert.Certificate[0]); err != nil {
		return
	}

	var keyPem []byte
	if keyPem, err = lib.EncodeKey(cert.PrivateKey); err != nil {
		return
	}

	fp := sha256.Sum256(cert.Leaf.Raw)
	secret := make([]byte, 64) // 64 * 8 = 512 bits of randomness
	if _, err = rand.Read(secret); err != nil {
		return err
	}

	var peerPem []byte
	addr := fmt.Sprintf("%s:%d", cmdIP(cmd, "peer-internal"), cmd.Uint16("port"))
	log.Printf("Registering %x on %s", fp, addr)
	if peerPem, err = lib.Register(addr, fp, secret); err != nil {
		return err
	}

	if err := save(cmd.String("boot"), "self.crt", certPem); err != nil {
		return err
	}
	if err := save(cmd.String("boot"), "self.key", keyPem); err != nil {
		return err
	}
	if err := save(cmd.String("boot"), "peer.crt", peerPem); err != nil {
		return err
	}

	return nil
}

func save(dir string, name string, pem []byte) error {
	return os.WriteFile(fmt.Sprintf("%s/%s", dir, name), pem, 0600)
}
