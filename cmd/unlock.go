package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Unlock(ctx context.Context, cmd *cli.Command) (err error) {
	var cert, key, peer []byte

	if cert, err = os.ReadFile(fmt.Sprintf("%s/self.crt", cmd.String("boot"))); errors.Is(err, os.ErrNotExist) {
		log.Println("No client cert found, exiting...")
		return nil
	} else if err != nil {
		return
	}

	if key, err = os.ReadFile(fmt.Sprintf("%s/self.key", cmd.String("boot"))); err != nil {
		return
	}

	if peer, err = os.ReadFile(fmt.Sprintf("%s/peer.crt", cmd.String("boot"))); err != nil {
		return
	}

	var secret []byte
	addr := fmt.Sprintf("%s:%d", cmdIP(cmd, "peer-public"), cmd.Uint16("port"))
	if secret, err = lib.Unlock(cmdIP(cmd, "self-external"), addr, cert, key, peer); err != nil {
		return
	}

	log.Printf("secret: %x", secret)

	return nil
}
