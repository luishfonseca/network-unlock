package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"
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

	if cmd.String("cryptsetup") == "" {
		log.Print("No cryptsetup binary provided, skipping enrollment...")
		return
	}

	var crypt string
	if crypt, err = backingDevice(cmd.String("crypt")); err != nil {
		return
	}

	secret := make([]byte, cmd.Int("random-bytes"))
	if n := subtle.XORBytes(secret, shareA, shareB); n < cmd.Int("random-bytes") {
		return fmt.Errorf("XOR of secret shares is too small: %d < %d", n, cmd.Int("random-bytes"))
	}

	return enrollLUKS(cmd.String("cryptsetup"), crypt, cmd.String("luks-key"), secret, cmd.Int("luks-slot"))
}

func backingDevice(mapperDevice string) (_ string, err error) {
	var st unix.Stat_t
	if err = unix.Stat(mapperDevice, &st); err != nil {
		return
	}

	backing := fmt.Sprintf("/sys/dev/block/%d:%d/slaves",
		unix.Major(st.Rdev),
		unix.Minor(st.Rdev),
	)

	var entries []os.DirEntry
	if entries, err = os.ReadDir(backing); err != nil {
		return
	}

	if len(entries) != 1 {
		return "", fmt.Errorf("expected 1 slave device, got %d", len(entries))
	}

	return filepath.Join("/dev", entries[0].Name()), nil
}

func enrollLUKS(cryptsetup, device, luksKey string, secret []byte, slot int) error {
	if output, err := exec.Command(
		cryptsetup, "luksKillSlot", device, strconv.Itoa(slot),
		"--batch-mode",
		"--key-file", luksKey,
	).CombinedOutput(); err != nil {
		log.Print(string(output))
	}

	log.Printf("Enrolling unlock key in LUKS slot %d", slot)

	cmd := exec.Command(
		cryptsetup, "luksAddKey", device,
		"--batch-mode",
		"--new-keyfile", "-",
		"--key-file", luksKey,
		"--key-slot", strconv.Itoa(slot),
	)
	cmd.Stdin = bytes.NewReader(secret)

	if output, err := cmd.CombinedOutput(); err != nil {
		log.Print(string(output))
		return err
	}

	return nil
}
