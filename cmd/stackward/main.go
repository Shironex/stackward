// Command stackward audits a self hosted Linux server (Docker, a PaaS,
// tunnels, intrusion prevention) and reports what is exposed and
// misconfigured. Version 0.1 only reads; it never changes the host.
package main

import (
	"os"

	"github.com/Shironex/stackward/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
