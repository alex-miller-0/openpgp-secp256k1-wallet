package utils

import (
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

func Keccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func Sha256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte("test"))
	return hasher.Sum(nil)
}
