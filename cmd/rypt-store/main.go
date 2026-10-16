// Command rypt-store is the rypt-store server and CLI client in one binary
// (core D6): `rypt-store server` runs the server, and every other
// subcommand is the CLI client.
package main

import (
	"os"

	"github.com/x6c-co/rypt-store/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
