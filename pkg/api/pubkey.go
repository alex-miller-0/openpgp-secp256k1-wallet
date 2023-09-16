package api

import (
	"fmt"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/openpgp"
)

// GetPub takes the user PIN for the connected smartcard and returns the
// uncompressed secp256k1 public key.
func GetPub(pin string) ([]byte, error) {
	// Export the pubkey
	pub, err := openpgp.GetPub(pin)
	if err != nil {
		return nil, fmt.Errorf("error getting public key from OpenPGP: %w", err)
	}
	// Make sure there is an secp256k1 key on the card by signing a test msg
	_, err = openpgp.SignECDSA(pin, []byte("test"))
	if err != nil {
		return nil, fmt.Errorf("key exists on card, but not secp256k1")
	}
	return pub, nil
}
