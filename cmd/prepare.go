package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	var pem map[string][]byte = map[string][]byte{}
	if pem["self.crt"], err = lib.EncodeCertificate(cert.Certificate[0]); err != nil {
		return
	}

	if pem["self.key"], err = lib.EncodeKey(cert.PrivateKey); err != nil {
		return
	}

	fp := sha256.Sum256(cert.Certificate[0])
	secret := make([]byte, cmd.Int("random-bytes"))
	if _, err = rand.Read(secret); err != nil {
		return
	}

	addr := fmt.Sprintf("%s:%d", cmdIP(cmd, "peer-internal"), cmd.Uint16("port"))
	log.Printf("Registering %x on %s", fp, addr)
	if pem["peer.crt"], err = lib.Register(cmdIP(cmd, "self-internal"), addr, fp, secret); err != nil {
		return
	}

	for k, v := range pem {
		if err = save(cmd.String("boot"), k, v); err != nil {
			return
		}
	}

	if cmd.String("cryptsetup") == "" {
		log.Print("The cryptsetup binary was not provided, skipping enrollment...")
		return
	}

	var crypt string
	if crypt, err = backingDevice(cmd.String("crypt")); err != nil {
		return
	}

	return enrollLUKS(cmd.String("cryptsetup"), crypt, cmd.String("luks-key"), secret, cmd.Int("luks-slot"))
}

func save(dir string, name string, pem []byte) error {
	return os.WriteFile(fmt.Sprintf("%s/%s", dir, name), pem, 0600)
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
