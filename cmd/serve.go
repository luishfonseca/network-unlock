package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Serve(ctx context.Context, cmd *cli.Command) (err error) {
	var cert tls.Certificate
	log.Printf("Generating certificate for public address %s", cmdIP(cmd, "public-address"))
	if cert, err = lib.GenerateCertificate("network-unlock-server", []net.IP{cmdIP(cmd, "public-address")}); err != nil {
		return err
	}

	errCh := make(chan error, 2)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		internal := fmt.Sprintf("%s:%d", cmdIP(cmd, "internal-address"), cmd.Uint16("port"))
		log.Printf("Register server starting on internal address: %s", internal)
		err := lib.ServeRegister(childCtx, cert, internal)
		errCh <- err
	}()

	go func() {
		var external string
		if cmdIP(cmd, "external-address") != nil {
			external = fmt.Sprintf("%s:%d", cmdIP(cmd, "external-address"), cmd.Uint16("port"))
		} else {
			external = fmt.Sprintf("%s:%d", cmdIP(cmd, "public-address"), cmd.Uint16("port"))
		}

		log.Printf("Unlock server starting on external address: %s", external)
		errCh <- lib.ServeUnlock(childCtx, cmd.Duration("ttl"), cert, external)
	}()

	return <-errCh
}
