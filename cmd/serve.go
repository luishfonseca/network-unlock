package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Serve(ctx context.Context, cmd *cli.Command) error {
	log.Printf("serve: generating certificate for %s", cmdIP(cmd, "public"))
	cert, err := lib.GenerateCertificate("network-unlock-server", []net.IP{cmdIP(cmd, "public")})
	if err != nil {
		return err
	}

	// Two listeners on different networks: register (internal, plain HTTP) and
	// unlock (external, mTLS). If either fails, we tear down both.
	errCh := make(chan error, 2)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		addr := cmdIP(cmd, "internal")
		internal := fmt.Sprintf("%s:%d", addr, cmd.Uint16("port"))
		log.Printf("serve: register server starting on %s", internal)
		err := lib.ServeRegister(childCtx, cert, internal, addr.To4() == nil)
		errCh <- err
	}()

	ttl := cmd.Duration("ttl")
	go func() {
		var addr net.IP
		if cmdIP(cmd, "external") != nil {
			addr = cmdIP(cmd, "external")
		} else {
			addr = cmdIP(cmd, "public")
		}

		external := fmt.Sprintf("%s:%d", addr, cmd.Uint16("port"))
		log.Printf("serve: unlock server starting on %s", external)
		errCh <- lib.ServeUnlock(childCtx, ttl, cert, external, addr.To4() == nil)
	}()

	ticker := time.NewTicker(ttl)
	go func() {
		for {
			select {
			case <-ticker.C:
				count := lib.CleanupEntries(ttl)
				if count > 0 {
					log.Printf("serve: removed %d expired entries", count)
				}
			case <-childCtx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	return <-errCh
}
