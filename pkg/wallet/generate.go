package wallet

import (
	"context"
	"flag"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/openpgp"
	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/ux"
	"github.com/google/subcommands"
)

const (
	GenerateDesc = "Generate a new secp256k1 keypair on a smartcard via OpenPGP"
)

type Generate struct {
	UserPin  string
	AdminPin string
}

func (*Generate) Name() string { return "generate" }

func (*Generate) Synopsis() string {
	return GenerateDesc
}

func (*Generate) Usage() string {
	return "generate [--user-pin <user pin>] [--admin-pin <admin pin>]\n\n" +
		"If PINs are not provided, you will be prompted to enter them.\n"
}

func (g *Generate) SetFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(
		&g.UserPin,
		"user-pin",
		"",
		"PIN (or passphrase) of the security key device",
	)
	flagSet.StringVar(
		&g.AdminPin,
		"admin-pin",
		"",
		"Admin PIN (or passphrase) of the security key device",
	)
}

func (g *Generate) Execute(
	_ context.Context,
	flagSet *flag.FlagSet,
	_ ...any,
) subcommands.ExitStatus {
	if g.UserPin == "" {
		ux.PromptForSecret("Enter user PIN: ", &g.UserPin)
	}
	if g.AdminPin == "" {
		ux.PromptForSecret("Enter admin PIN: ", &g.AdminPin)
	}
	pub, err := openpgp.GenerateSecp256k1(g.AdminPin, g.UserPin)
	if err != nil {
		ux.Errorf("Error generating secp256k1 key: %s", err.Error())
		return subcommands.ExitFailure
	}
	ux.Passf("Generated secp256k1 key (%d):\n% x\n", len(pub), pub)
	return subcommands.ExitSuccess
}
