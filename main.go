package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/luishfonseca/network-unlock/cmd"
	"github.com/urfave/cli/v3"
)

var Version = "dev"

func main() {
	cmd := &cli.Command{
		Commands: []*cli.Command{
			{
				Name:    "serve",
				Aliases: []string{"s"},
				Action:  cmd.Serve,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Required: true,
						Name:     "internal-address",
						Aliases:  []string{"int"},
					},
					&cli.StringFlag{
						Name:    "external-address",
						Aliases: []string{"ext"},
					},
					&cli.StringFlag{
						Required: true,
						Name:     "public-address",
						Aliases:  []string{"pub"},
					},
					&cli.Uint16Flag{
						Name:    "port",
						Aliases: []string{"p"},
						Value:   9745,
					},
					&cli.DurationFlag{
						Name:  "ttl",
						Value: time.Duration(5 * time.Minute),
					},
				},
			},
		},
		Version: Version,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
