package cmd

import (
	"context"
	"log"

	"github.com/luishfonseca/network-unlock/lib"
	"github.com/urfave/cli/v3"
)

func Cleanup(ctx context.Context, cmd *cli.Command) (err error) {
	log.Print("Clearing key from LUKS slot 7")
	if output, err := lib.KillSlot(cmd.String("luks-crypt"), cmd.String("luks-key"), cmd.Int("luks-slot")); err != nil {
		log.Print(string(output))
		return err
	}

	return nil
}
