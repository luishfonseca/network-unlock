package cmd

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Serve(ctx context.Context, cmd *cli.Command) (err error) {
	var cert tls.Certificate
	log.Printf("Generating certificate for public address %s", cmd.String("public-address"))
	if cert, err = lib.GenerateCertificate("network-unlock-server", cmd.String("public-address")); err != nil {
		return err
	}

	errCh := make(chan error, 2)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		log.Printf("Register server starting on internal address: %s:%d", cmd.String("internal-address"), cmd.Uint16("port"))
		err := lib.ServeRegister(childCtx, cert, cmd.String("internal-address"), cmd.Uint16("port"))
		errCh <- err
	}()

	go func() {
		externalAddress := cmd.String("external-address")
		if externalAddress == "" {
			externalAddress = cmd.String("public-address")
		}

		log.Printf("Unlock server starting on external address: %s:%d", externalAddress, cmd.Uint16("port"))
		errCh <- lib.ServeUnlock(childCtx, cmd.Duration("ttl"), cert, externalAddress, cmd.Uint16("port"))
	}()

	return <-errCh
}
