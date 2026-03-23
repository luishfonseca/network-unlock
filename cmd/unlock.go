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

func Unlock(ctx context.Context, cmd *cli.Command) (err error) {
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
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %s", dir, err.Error())
	}

	defer os.Remove(cmd.String("fifo"))
	if err = unix.Mkfifo(cmd.String("fifo"), 0o600); err != nil {
		return fmt.Errorf("mkfifo %s: %s", cmd.String("fifo"), err.Error())
	}

	var cert, key, peer []byte
	certPath := fmt.Sprintf("%s/self.crt", cmd.String("dir"))
	defer os.Remove(certPath)
	if cert, err = os.ReadFile(certPath); err != nil {
		return fmt.Errorf("read %s: %s", certPath, err.Error())
	}

	keyPath := fmt.Sprintf("%s/self.key", cmd.String("dir"))
	defer os.Remove(keyPath)
	if key, err = os.ReadFile(keyPath); err != nil {
		return fmt.Errorf("read %s: %s", keyPath, err.Error())
	}

	peerPath := fmt.Sprintf("%s/peer.crt", cmd.String("dir"))
	defer os.Remove(peerPath)
	if peer, err = os.ReadFile(peerPath); err != nil {
		return fmt.Errorf("read %s: %s", peerPath, err.Error())
	}

	childCtx, cancel := context.WithDeadline(ctx, time.Now().Add(cmd.Duration("timeout")))
	defer cancel()

	var shareA []byte
	log.Printf("Retrieving secret share from %s", cmdIP(cmd, "peer-public"))
	if shareA, err = lib.Unlock(childCtx, cmdIP(cmd, "self-external"), fmt.Sprintf("%s:%d", cmdIP(cmd, "peer-public"), cmd.Uint16("port")), cert, key, peer); err != nil {
		return
	}

	var shareB []byte
	sharePath := fmt.Sprintf("%s/share.key", cmd.String("dir"))
	defer os.Remove(sharePath)
	if shareB, err = os.ReadFile(sharePath); err != nil {
		return fmt.Errorf("read %s: %s", sharePath, err.Error())
	}

	secret := make([]byte, len(shareA))
	subtle.XORBytes(secret, shareA, shareB)

	log.Printf("Secret is ready on %s", cmd.String("fifo"))
	ready()

	var f *os.File
	if f, err = os.OpenFile(cmd.String("fifo"), os.O_WRONLY, os.ModeNamedPipe); err != nil {
		return fmt.Errorf("open %s: %s", cmd.String("fifo"), err.Error())
	}
	defer f.Close()

	if _, err = f.Write(secret); err != nil {
		return
	}
	log.Print("Secret was read")

	return nil
}
