package utils

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	HashTypeSha256    = "sha256"
	HashTypeKeccak256 = "keccak"
	HashTypePrehashed = "none"
)

func Hash(data []byte, hashType string) ([]byte, error) {
	switch hashType {
	case HashTypeSha256:
		return Sha256(data), nil
	case HashTypeKeccak256:
		return Keccak256(data), nil
	case HashTypePrehashed:
		if len(data) != 32 {
			return nil, fmt.Errorf(
				"prehashed data must be 32 bytes, got %d",
				len(data),
			)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported hash type: %s", hashType)
	}
}

func Keccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func Sha256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}
