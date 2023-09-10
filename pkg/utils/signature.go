package utils

import (
	"bytes"

	"github.com/ethereum/go-ethereum/crypto"
)

func ValidateSig(msgHash, sig, pub []byte) bool {
	sigWithRecovery := append(sig, 0)
	sigPub, err := crypto.Ecrecover(msgHash, sigWithRecovery)
	if err != nil {
		return false
	}
	if bytes.Equal(sigPub, pub) {
		return true
	}
	sigWithRecovery[len(sigWithRecovery)-1] = 0x01
	sigPub, err = crypto.Ecrecover(msgHash, sigWithRecovery)
	if err != nil {
		return false
	}
	return bytes.Equal(sigPub, pub)
}
