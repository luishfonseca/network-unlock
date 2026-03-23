package cmd

import (
	"context"
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

	log.Printf("Retrieving secret from %s", cmdIP(cmd, "peer-public"))
	var secret []byte
	if secret, err = remoteSecret(
		cmdIP(cmd, "self-external"),
		cmdIP(cmd, "peer-public"),
		cmd.Uint16("port"),
		cmd.String("boot"),
	); err != nil {
		return
	}

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
	return nil
}

func remoteSecret(from, to net.IP, port uint16, boot string) (_ []byte, err error) {
	var cert, key, peer []byte
	if cert, err = os.ReadFile(fmt.Sprintf("%s/self.crt", boot)); err != nil {
		return
	}

	if key, err = os.ReadFile(fmt.Sprintf("%s/self.key", boot)); err != nil {
		return
	}

	if peer, err = os.ReadFile(fmt.Sprintf("%s/peer.crt", boot)); err != nil {
		return
	}

	return lib.Unlock(from, fmt.Sprintf("%s:%d", to, port), cert, key, peer)
}
