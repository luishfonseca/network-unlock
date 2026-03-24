package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Prepare(ctx context.Context, cmd *cli.Command) error {
	log.Printf("prepare: generating ephemeral certificate")

	cert, err := lib.GenerateCertificate("network-unlock-client", []net.IP{
		cmdIP(cmd, "self-internal"),
		cmdIP(cmd, "self-public"),
	})
	if err != nil {
		return err
	}

	store := map[string][]byte{}
	store["self.crt"], err = lib.EncodeCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	store["self.key"], err = lib.EncodeKey(cert.PrivateKey)
	if err != nil {
		return err
	}

	// Secret sharing: generate two random shares (A, B) such that the actual
	// LUKS key is A XOR B. Share A goes to the server, share B stays on the
	// local boot partition. Neither share alone reveals the key.
	fp := sha256.Sum256(cert.Certificate[0])
	shareA := make([]byte, cmd.Int("random-bytes"))
	defer subtle.XORBytes(shareA, shareA, shareA) // zero on exit to limit secret lifetime in memory
	_, err = rand.Read(shareA)
	if err != nil {
		return err
	}

	shareB := make([]byte, cmd.Int("random-bytes"))
	defer subtle.XORBytes(shareB, shareB, shareB)
	_, err = rand.Read(shareB)
	if err != nil {
		return err
	}
	store["share.key"] = shareB

	childCtx, cancel := context.WithDeadline(ctx, time.Now().Add(cmd.Duration("timeout")))
	defer cancel()

	addr := fmt.Sprintf("%s:%d", cmdIP(cmd, "peer-internal"), cmd.Uint16("port"))
	log.Printf("prepare: storing secret share on %s (%x)", addr, fp)
	store["peer.crt"], err = lib.Register(childCtx, cmdIP(cmd, "self-internal"), addr, fp, shareA)
	if err != nil {
		return err
	}

	err = os.MkdirAll(cmd.String("dir"), 0700)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", cmd.String("dir"), err)
	}

	for k, v := range store {
		path := fmt.Sprintf("%s/%s", cmd.String("dir"), k)
		err = os.WriteFile(path, v, 0600)
		if err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	secret := make([]byte, cmd.Int("random-bytes"))
	defer subtle.XORBytes(secret, secret, secret)
	if n := subtle.XORBytes(secret, shareA, shareB); n < cmd.Int("random-bytes") {
		return fmt.Errorf("xor of secret shares too small: %d < %d", n, cmd.Int("random-bytes"))
	}

	// Clear any previous ephemeral key from the slot before enrolling the new one.
	// This is idempotent -- TryKillSlot succeeds even if the slot is already empty.
	err = lib.TryKillSlot(cmd.String("luks-crypt"), cmd.String("luks-key"), cmd.Int("luks-slot"))
	if err != nil {
		return err
	}

	// Enroll A XOR B as an ephemeral LUKS key. After the next boot unlocks with
	// it, cleanup will remove it -- so each boot cycle gets a fresh key.
	log.Printf("prepare: enrolling unlock key in LUKS slot %d", cmd.Int("luks-slot"))
	return lib.AddKey(cmd.String("luks-crypt"), "-", cmd.String("luks-key"), cmd.Int("luks-slot"), secret)
}
