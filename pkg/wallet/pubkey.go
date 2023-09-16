package wallet

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/api"
	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/ux"
	"github.com/google/subcommands"
)

const (
	PubKeyDesc = "Print the uncompressed secp256k1 public key on the card"
)

type PubKey struct {
	UserPin  string
	AdminPin string
}

func (*PubKey) Name() string { return "pubkey" }

func (*PubKey) Synopsis() string {
	return PubKeyDesc
}

func (*PubKey) Usage() string {
	return "pubkey [--user-pin <user pin>]\n\n" +
		"If PIN is not provided, you will be prompted to enter it.\n"
}

func (p *PubKey) SetFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(
		&p.UserPin,
		"user-pin",
		"",
		"PIN (or passphrase) of the security key device",
	)
}

func (p *PubKey) Execute(
	_ context.Context,
	flagSet *flag.FlagSet,
	_ ...any,
) subcommands.ExitStatus {
	if p.UserPin == "" {
		ux.PromptForSecret("Enter user PIN: ", &p.UserPin)
	}
	pub, err := api.GetPub(p.UserPin)
	if err != nil {
		ux.Errorf(err.Error())
		return subcommands.ExitFailure
	}
	ux.Passln(fmt.Sprintf("Public key: %s", hex.EncodeToString(pub)))
	return subcommands.ExitSuccess
}
