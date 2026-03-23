package cmd

import (
	"context"
	"log"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Cleanup(ctx context.Context, cmd *cli.Command) error {
	log.Printf("cleanup: clearing key from LUKS slot %d", cmd.Int("luks-slot"))
	return lib.TryKillSlot(cmd.String("luks-crypt"), cmd.String("luks-key"), cmd.Int("luks-slot"))
}
