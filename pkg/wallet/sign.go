package wallet

import (
	"context"
	"encoding/hex"
	"flag"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/openpgp"
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
}

func (*Sign) Name() string { return "sign" }

func (*Sign) Synopsis() string {
	return SignDesc
}

func (*Sign) Usage() string {
	return "sign [--user-pin <user pin>] <data>\n\n" +
		"If PIN is not provided, you will be prompted to enter it.\n"
}

func (s *Sign) SetFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(
		&s.UserPin,
		"user-pin",
		"",
		"PIN (or passphrase) of the security key device",
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
		ux.Errorln("Data must be hex encoded")
		return subcommands.ExitFailure
	}
	hash := utils.Keccak256(msg)
	sig, err := openpgp.SignECDSA(s.UserPin, hash)
	if err != nil {
		ux.Errorf("Error signing data: %s", err.Error())
		return subcommands.ExitFailure
	}
	pub, err := openpgp.GetPub(s.UserPin)
	if err != nil {
		ux.Errorf("Error getting public key from OpenPGP: %s", err.Error())
		return subcommands.ExitFailure
	}
	if !utils.ValidateSig(hash, sig, pub) {
		return subcommands.ExitFailure
	}
	ux.Passln(hex.EncodeToString(sig))
	return subcommands.ExitSuccess
}
