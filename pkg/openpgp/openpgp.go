package openpgp

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/utils"
)

type (
	UifOption byte
	KeyType   byte
)

const (
	// ISO7816 constants
	// https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/
	// ISO7816.html#CLA_ISO7816
	Cla byte = 0x00
	// https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/
	// ISO7816.html#SW_NO_ERROR
	NoErrorByte1 byte = 0x90
	NoErrorByte2 byte = 0x00

	// OpenPGP applet constants
	// See: https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf
	// Instructions
	InsVerify            byte = 0x20
	InsSecurityOperation byte = 0x2A
	InsAsymmetricKeyPair byte = 0x47
	InsPutData           byte = 0xDA

	// P1/P2 options
	SignP1            byte = 0x9E
	SignP2            byte = 0x9A
	PutDataChangeAlgo byte = 0xC1
	GenerateKeyP1     byte = 0x80
	ExportPubP1       byte = 0x81
	VerifyPw1P1       byte = 0x81
	VerifyPw3P1       byte = 0x83

	// Data object tags
	EcdsaTag           byte = 0x86
	AlgorithmECDSATag  byte = 0x13
	GenerateWithPubTag byte = 0xFF

	// Package constants
	Uncompressed byte = 0x04

	PubKeySz = 65
	RSz      = 32
)

var (
	SigSelector    = []byte{0xB6, 0x00}
	PubKeyTemplate = []byte{0x7F, 0x49}
	// It took some digging to find this, as it's not in the OpenPGP spec.
	// https://kjur.github.io/jsrsasign/api/symbols/src/crypto-1.1.js.html
	OIDSecp256k1 = []byte{0x2b, 0x81, 0x04, 0x00, 0x0a}
)

func GetPub(userPin string) ([]byte, error) {
	err := unlock(userPin, false)
	if err != nil {
		return nil, err
	}
	data, err := exportPub()
	if err != nil {
		return nil, err
	}
	return parsePubkey(data)
}

func GenerateSecp256k1(adminPin, userPin string) ([]byte, error) {
	err := unlock(adminPin, true)
	if err != nil {
		return nil, err
	}
	// Update algorithm on the card
	data := []byte{AlgorithmECDSATag}
	data = append(data, OIDSecp256k1...)
	data = append(data, GenerateWithPubTag)
	_, err = sendAPDU(InsPutData, 0x00, PutDataChangeAlgo, data)
	if err != nil {
		return nil, fmt.Errorf("error updating algorithm on card %w", err)
	}
	// Check if the card already has a key loaded and exit if so
	if keyOnCard() {
		return nil, fmt.Errorf("key already exists on card. Please reset it")
	}
	// Generate key
	_, err = sendAPDU(InsAsymmetricKeyPair, GenerateKeyP1, 0x00, SigSelector)
	if err != nil {
		return nil, fmt.Errorf("error generating key %w", err)
	}
	// Export the pubkey and make sure it conforms
	resp, err := sendAPDU(InsAsymmetricKeyPair, ExportPubP1, 0x00, SigSelector)
	if err != nil {
		return nil, err
	}
	pub, err := parsePubkey(resp)
	if err != nil {
		return nil, err
	} else if len(pub) != PubKeySz {
		// Sometimes OpenPGP will generate a pubkey that is not 65 bytes...
		// but if you keep generating it will eventually make the right key.
		// I cannot find this documented anywhere but running a test many times
		// should prove that this is fine.
		return GenerateSecp256k1(adminPin, userPin)
	}
	// Annoyingly, we also need to unlock Pw1 to sign
	err = unlock(userPin, false)
	if err != nil {
		return nil, err
	}
	// Test a signature and validate we have the correct pubkey
	h := utils.Sha256([]byte("test"))
	sig, err := sign(h)
	if err != nil {
		return nil, err
	}
	if !utils.ValidateSig(h, sig, pub) {
		return nil, fmt.Errorf(
			"failed to generate key pair. Try resetting the device",
		)
	}
	return pub, nil
}

func SignECDSA(userPin string, hash []byte) ([]byte, error) {
	err := unlock(userPin, false)
	if err != nil {
		return nil, err
	}
	return sign(hash)
}

func keyOnCard() bool {
	pub, _ := exportPub()
	return len(pub) != 0
}

func exportPub() ([]byte, error) {
	resp, err := sendAPDU(InsAsymmetricKeyPair, ExportPubP1, 0x00, SigSelector)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func sign(hash []byte) ([]byte, error) {
	// TODO: First ensure that signing key is secp256k1
	sig, err := sendAPDU(InsSecurityOperation, SignP1, SignP2, hash)
	if err != nil {
		return nil, fmt.Errorf("error in sign APDU: %w", err)
	}
	// As with generating keys, sometimes OpenPGP returns signatures that are
	// not 64 bytes. Once again, the solution is to keep retrying.
	if len(sig) != RSz*2 {
		return sign(hash)
	}
	return sig, nil
}

func unlock(pin string, admin bool) error {
	pinBytes := []byte(pin)
	p1 := VerifyPw1P1
	if admin {
		p1 = VerifyPw3P1
	}
	resp, err := sendAPDU(InsVerify, 0x00, p1, pinBytes)
	if err != nil {
		return fmt.Errorf("error unlocking %s", err.Error())
	} else if len(resp) > 0 {
		return fmt.Errorf("unexpected data in response")
	}
	return nil
}

// SendAPDU sends an APDU command to the OpenPGP applet on the smartcard
func sendAPDU(ins, p1, p2 byte, data []byte) ([]byte, error) {
	apdu := []string{
		fmt.Sprintf("%02x", Cla),
		fmt.Sprintf("%02x", ins),
		fmt.Sprintf("%02x", p1),
		fmt.Sprintf("%02x", p2),
		fmt.Sprintf("%02x", len(data)),
	}
	if len(data) > 0 {
		apdu = append(apdu, fmt.Sprintf("%x", data))
	}
	command := append([]string{"scd", "apdu"}, apdu...)
	out, err := exec.Command(
		"gpg-connect-agent",
		"--hex",
		strings.Join(command, " "),
		"/bye",
	).Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	outData := []byte{}
	for _, field := range fields {
		b, err := hex.DecodeString(field)
		if err == nil && len(b) == 1 {
			outData = append(outData, b...)
		}
	}
	return processResponse(outData)
}

func processResponse(resp []byte) ([]byte, error) {
	if len(resp) < 2 {
		return nil, fmt.Errorf("invalid response from card")
	}
	got1 := resp[len(resp)-2]
	got2 := resp[len(resp)-1]
	if got1 != NoErrorByte1 || got2 != NoErrorByte2 {
		return nil, fmt.Errorf("APDU error: %02x %02x", got1, got2)
	}
	return resp[:len(resp)-2], nil
}

func parsePubkey(data []byte) ([]byte, error) {
	off := 0
	if data[off] != PubKeyTemplate[0] || data[off+1] != PubKeyTemplate[1] {
		return nil, fmt.Errorf("invalid public key template")
	}
	off += 2
	if data[off] != PubKeySz+2 {
		return nil, fmt.Errorf("invalid public key template length")
	}
	off += 1
	if data[off] != EcdsaTag {
		return nil, fmt.Errorf(
			"invalid public key type. Signing key must be ECDSA",
		)
	}
	off += 1
	if data[off] != PubKeySz {
		return nil, fmt.Errorf("invalid public key length")
	}
	off += 1
	if data[off] != Uncompressed {
		return nil, fmt.Errorf("invalid public key compression")
	}
	// The rest of the object *should* be R|S, but the card will return pubkeys
	// anywhere from 65 (correct) to 71 bytes. I cannot find any documentation
	// about why this is, but we can keep generating until we get a 65 byte key.
	pubkey := data[off:]
	return pubkey, nil
}
