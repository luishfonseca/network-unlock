package cmd

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"
)

func Unlock(ctx context.Context, cmd *cli.Command) error {
	// sd_notify(READY) tells systemd-cryptsetup the FIFO is available to read.
	// The deferred call ensures we notify even on error paths, so cryptsetup
	// doesn't hang waiting for us forever (it will just fail to read the key).
	var once sync.Once
	ready := func() {
		once.Do(func() {
			if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
				log.Print(err)
			}
		})
	}
	defer ready()

	dir := path.Dir(cmd.String("fifo"))
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	defer os.Remove(cmd.String("fifo"))
	err = unix.Mkfifo(cmd.String("fifo"), 0o600)
	if err != nil {
		return fmt.Errorf("mkfifo %s: %w", cmd.String("fifo"), err)
	}

	// Read and delete credentials eagerly -- they're ephemeral and should not
	// survive on the unencrypted boot partition longer than necessary.
	certPath := fmt.Sprintf("%s/self.crt", cmd.String("dir"))
	defer os.Remove(certPath)
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", certPath, err)
	}

	keyPath := fmt.Sprintf("%s/self.key", cmd.String("dir"))
	defer os.Remove(keyPath)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", keyPath, err)
	}

	peerPath := fmt.Sprintf("%s/peer.crt", cmd.String("dir"))
	defer os.Remove(peerPath)
	peer, err := os.ReadFile(peerPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", peerPath, err)
	}

	childCtx, cancel := context.WithDeadline(ctx, time.Now().Add(cmd.Duration("timeout")))
	defer cancel()

	log.Printf("unlock: retrieving secret share from %s", cmdIP(cmd, "peer-public"))
	shareA, err := lib.Unlock(childCtx, cmdIP(cmd, "self-external"), fmt.Sprintf("%s:%d", cmdIP(cmd, "peer-public"), cmd.Uint16("port")), cert, key, peer)
	if err != nil {
		return err
	}
	defer subtle.XORBytes(shareA, shareA, shareA)

	sharePath := fmt.Sprintf("%s/share.key", cmd.String("dir"))
	defer os.Remove(sharePath)
	shareB, err := os.ReadFile(sharePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", sharePath, err)
	}
	defer subtle.XORBytes(shareB, shareB, shareB)

	if len(shareA) != len(shareB) {
		return fmt.Errorf("share length mismatch: %d != %d", len(shareA), len(shareB))
	}

	secret := make([]byte, len(shareA))
	defer subtle.XORBytes(secret, secret, secret)
	subtle.XORBytes(secret, shareA, shareB)

	// Notify *before* opening the FIFO for writing -- the open() blocks until
	// systemd-cryptsetup opens it for reading, so sd_notify must come first.
	log.Printf("unlock: secret ready on %s", cmd.String("fifo"))
	ready()

	f, err := os.OpenFile(cmd.String("fifo"), os.O_WRONLY, os.ModeNamedPipe)
	if err != nil {
		return fmt.Errorf("open %s: %w", cmd.String("fifo"), err)
	}
	defer f.Close()

	_, err = f.Write(secret)
	if err != nil {
		return err
	}
	log.Print("unlock: secret was read")

	return nil
}
