package cmd

import (
	"fmt"
	"net"

	"github.com/urfave/cli/v3"
)

type ip struct{ net.IP }
type ipValue ip

type IPFlag = cli.FlagBase[ip, cli.NoConfig, ipValue]

func (v ipValue) Get() any {
	return ip(v).IP
}

func (ipValue) Create(val ip, p *ip, _ cli.NoConfig) cli.Value {
	*p = val
	return (*ipValue)(p)
}

func (v *ipValue) Set(s string) error {
	if parsed := net.ParseIP(s); parsed != nil {
		*v = ipValue(ip{parsed})
		return nil
	}
	return fmt.Errorf("unable to parse ip")
}

func (v ipValue) String() string {
	return ip(v).IP.String()
}

func (ipValue) ToString(val ip) string {
	return ipValue(val).String()
}

func cmdIP(cmd *cli.Command, name string) net.IP {
	if v, ok := cmd.Value(name).(net.IP); ok {
		return v
	}
	return nil
}
