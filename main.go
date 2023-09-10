package main

import (
	"context"
	"flag"
	"os"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/wallet"
	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(&wallet.Generate{}, "")
	subcommands.Register(&wallet.PubKey{}, "")
	subcommands.Register(&wallet.Sign{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
