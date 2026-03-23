package cmd

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
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

	cleanup := func() {
		ready()
		os.Remove(cmd.String("fifo"))
	}
	defer cleanup()

	if err = syscall.Mkfifo(cmd.String("fifo"), 0o600); err != nil {
		return
	}

	log.Printf("Retrieving secret share from %s", cmdIP(cmd, "peer-public"))
	var shareA []byte
	if shareA, err = remoteShare(
		cmdIP(cmd, "self-external"),
		cmdIP(cmd, "peer-public"),
		cmd.Uint16("port"),
		cmd.String("boot"),
	); err != nil {
		return
	}

	var shareB []byte
	sharePath := fmt.Sprintf("%s/share.key", cmd.String("boot"))
	defer os.Remove(sharePath)
	if shareB, err = os.ReadFile(sharePath); err != nil {
		return
	}

	secret := make([]byte, len(shareA))
	subtle.XORBytes(secret, shareA, shareB)

	// clean shares from memory
	subtle.XORBytes(shareA, shareA, shareA)
	subtle.XORBytes(shareB, shareB, shareB)

	log.Printf("Secret is ready on %s", cmd.String("fifo"))
	ready()

	var f *os.File
	if f, err = os.OpenFile(cmd.String("fifo"), os.O_WRONLY, os.ModeNamedPipe); err != nil {
		return
	}
	defer f.Close()

	if _, err = f.Write(secret); err != nil {
		return
	}
	log.Print("Secret was read")

	// clean secret from memory
	subtle.XORBytes(secret, secret, secret)

	return nil
}

func remoteShare(from, to net.IP, port uint16, boot string) (_ []byte, err error) {
	var cert, key, peer []byte

	certPath := fmt.Sprintf("%s/self.crt", boot)
	defer os.Remove(certPath)
	if cert, err = os.ReadFile(certPath); err != nil {
		return
	}

	keyPath := fmt.Sprintf("%s/self.key", boot)
	defer os.Remove(keyPath)
	if key, err = os.ReadFile(keyPath); err != nil {
		return
	}

	peerPath := fmt.Sprintf("%s/peer.crt", boot)
	defer os.Remove(peerPath)
	if peer, err = os.ReadFile(peerPath); err != nil {
		return
	}

	return lib.Unlock(from, fmt.Sprintf("%s:%d", to, port), cert, key, peer)
}
