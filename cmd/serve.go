package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Serve(ctx context.Context, cmd *cli.Command) (err error) {
	var cert tls.Certificate
	log.Printf("Generating certificate for public address %s", cmdIP(cmd, "public"))
	if cert, err = lib.GenerateCertificate("network-unlock-server", []net.IP{cmdIP(cmd, "public")}); err != nil {
		return err
	}

	errCh := make(chan error, 2)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		internal := fmt.Sprintf("%s:%d", cmdIP(cmd, "internal"), cmd.Uint16("port"))
		log.Printf("Register server starting on internal address: %s", internal)
		err := lib.ServeRegister(childCtx, cert, internal)
		errCh <- err
	}()

	ttl := cmd.Duration("ttl")
	go func() {
		var external string
		if cmdIP(cmd, "external-address") != nil {
			external = fmt.Sprintf("%s:%d", cmdIP(cmd, "external"), cmd.Uint16("port"))
		} else {
			external = fmt.Sprintf("%s:%d", cmdIP(cmd, "public"), cmd.Uint16("port"))
		}

		log.Printf("Unlock server starting on external address: %s", external)
		errCh <- lib.ServeUnlock(childCtx, ttl, cert, external)
	}()

	ticker := time.NewTicker(ttl)
	go func() {
		for {
			select {
			case <-ticker.C:
				count := lib.CleanupEntries(ttl)
				if count > 0 {
					log.Printf("Removed %d expired entries", count)
				}
			case <-childCtx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	return <-errCh
}
