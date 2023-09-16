package wallet

import (
	"context"
	"encoding/hex"
	"flag"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/api"
	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/utils"
	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/ux"
	"github.com/google/subcommands"
)

const (
	SignDesc = "Print the uncompressed secp256k1 public key on the card"
)

type Sign struct {
	UserPin  string
	AdminPin string
	Hash     string
}

func (*Sign) Name() string { return "sign" }

func (*Sign) Synopsis() string {
	return SignDesc
}

func (*Sign) Usage() string {
	return "sign [--user-pin <user_pin> --hash <hash>] <data>\n\n" +
		"If PIN is not provided, you will be prompted to enter it.\n"
}

func (s *Sign) SetFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(
		&s.UserPin,
		"user-pin",
		"",
		"PIN (or passphrase) of the security key device",
	)
	flagSet.StringVar(
		&s.Hash,
		"hash",
		"sha256",
		"Hash type to use (sha256 | keccak256 | none)",
	)
}

func (s *Sign) Execute(
	_ context.Context,
	flagSet *flag.FlagSet,
	_ ...any,
) subcommands.ExitStatus {
	if s.UserPin == "" {
		ux.PromptForSecret("Enter user PIN: ", &s.UserPin)
	}
	data := flagSet.Arg(0)
	if data[:2] == "0x" {
		data = data[2:]
	}
	msg, err := hex.DecodeString(data)
	if err != nil {
		if s.Hash == utils.HashTypePrehashed {
			ux.Errorln(
				"Could not parse input. Please provide a hex string.",
			)
			return subcommands.ExitFailure
		}
		for _, c := range data {
			if c > 127 {
				ux.Errorln(
					"Could not parse input. Please provide an ASCII or hex string.",
				)
				return subcommands.ExitFailure
			}
		}
		msg = []byte(data)
	}
	sig, err := api.Sign(msg, s.UserPin, s.Hash)
	if err != nil {
		ux.Errorln(err.Error())
		return subcommands.ExitFailure
	}
	ux.Passln(hex.EncodeToString(sig))
	return subcommands.ExitSuccess
}
