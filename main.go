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
					&cmd.IPFlag{
						Required: true,
						Name:     "internal",
						Aliases:  []string{"int"},
					},
					&cmd.IPFlag{
						Name:        "external",
						DefaultText: "public",
						Aliases:     []string{"ext"},
					},
					&cmd.IPFlag{
						Required: true,
						Name:     "public",
						Aliases:  []string{"pub"},
					},
					&cli.DurationFlag{
						Name:  "ttl",
						Value: time.Duration(5 * time.Minute),
					},
				},
			},
			{
				Name:    "prepare",
				Aliases: []string{"p"},
				Action:  cmd.Prepare,
				Flags: []cli.Flag{
					&cmd.IPFlag{
						Required: true,
						Name:     "self-internal",
						Aliases:  []string{"sint"},
					},
					&cmd.IPFlag{
						Required: true,
						Name:     "self-public",
						Aliases:  []string{"spub"},
					},
					&cmd.IPFlag{
						Required: true,
						Name:     "peer-internal",
						Aliases:  []string{"pint"},
					},
				},
			},
		},
		Flags: []cli.Flag{
			&cli.Uint16Flag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   9745,
			},
		},
		Version: Version,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
