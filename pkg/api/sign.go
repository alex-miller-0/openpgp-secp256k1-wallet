package api

import (
	"fmt"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/openpgp"
	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/utils"
)

// Sign takes a message, the user PIN of the connected smartcard, and a
// hash type, and returns an secp256k1 ECDSA signature by the smartcard.
// The hash type can be one of the following:
// - "sha256"
// - "keccak256"
func Sign(data []byte, pin, hashType string) ([]byte, error) {
	pub, err := openpgp.GetPub(pin)
	if err != nil {
		return nil, fmt.Errorf("error getting public key from OpenPGP: %w", err)
	}
	hash, err := utils.Hash(data, hashType)
	if err != nil {
		return nil, fmt.Errorf("error hashing data: %w", err)
	}
	sig, err := openpgp.SignECDSA(pin, hash)
	if err != nil {
		return nil, fmt.Errorf("error signing data: %w", err)
	}
	if !utils.ValidateSig(hash, sig, pub) {
		return nil, fmt.Errorf("signature validation failed")
	}
	return sig, nil
}

// SignPrehashed takes a prehashed message and the user PIN of the connected
// smartcard, and returns an secp256k1 ECDSA signature by the smartcard.
// The data must be 32 bytes.
func SignPrehashed(data []byte, pin string) ([]byte, error) {
	return Sign(data, pin, utils.HashTypePrehashed)
}
