package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
		return
	}

	store := map[string][]byte{}
	if store["self.crt"], err = lib.EncodeCertificate(cert.Certificate[0]); err != nil {
		return
	}

	if store["self.key"], err = lib.EncodeKey(cert.PrivateKey); err != nil {
		return
	}

	fp := sha256.Sum256(cert.Certificate[0])
	shareA := make([]byte, cmd.Int("random-bytes"))
	if _, err = rand.Read(shareA); err != nil {
		return
	}
	shareB := make([]byte, cmd.Int("random-bytes"))
	if _, err = rand.Read(shareB); err != nil {
		return
	}
	store["share.key"] = shareB

	addr := fmt.Sprintf("%s:%d", cmdIP(cmd, "peer-internal"), cmd.Uint16("port"))
	log.Printf("Storing secret share on %s (%x)", addr, fp)
	if store["peer.crt"], err = lib.Register(cmdIP(cmd, "self-internal"), addr, fp, shareA); err != nil {
		return
	}

	for k, v := range store {
		if err = os.WriteFile(fmt.Sprintf("%s/%s", cmd.String("boot"), k), v, 0600); err != nil {
			return
		}
	}

	secret := make([]byte, cmd.Int("random-bytes"))
	if n := subtle.XORBytes(secret, shareA, shareB); n < cmd.Int("random-bytes") {
		return fmt.Errorf("XOR of secret shares is too small: %d < %d", n, cmd.Int("random-bytes"))
	}

	if output, err := lib.KillSlot(cmd.String("luks-crypt"), cmd.String("luks-key"), cmd.Int("luks-slot")); err != nil {
		log.Print(string(output))
		// keep going
	}

	log.Printf("Enrolling unlock key in LUKS slot %d", cmd.Int("luks-slot"))
	if output, err := lib.AddKey(cmd.String("luks-crypt"), "-", cmd.String("luks-key"), cmd.Int("luks-slot"), secret); err != nil {
		log.Print(string(output))
		return err
	}

	return nil
}
