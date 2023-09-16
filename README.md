# OpenPGP Secp256k1 Smartcard Wallet

Turn your smartcard (e.g. Yubikey) into a secp256k1 wallet! This repo provides:

* A CLI for generating a keypair on your smartcard and signing messages with it
* An API for signing and exporting the public key from your smartcard device

### ⚠️  A Word of Caution

Although you can turn an inexpensive smartcard hardware device into a signer, it is inferior to using a true hardware wallet, and should not be a replacement for one. Yubikeys do not have a display, so all data must pass through your (presumably internet-connected) general purpose computer. Although this tool will help you generate a key securely (i.e. on the device, where it cannot be exported), you have no way to verify what you are signing on the secure device, which reduces the system's safety.

This repo was designed for multisig setups where several secondary signers are distributed, but if you are securing a large amount of value, you should ensure your primary signer is using a hardware wallet or secure setup. Be safe! ✌️

## Using the CLI

You are likely using a Yubikey; if you are, read all about getting it setup [here](https://gist.github.com/Riebart/64c53f7d4ad4f5897b22c43ac0410ae5#generating-pgp-keys). You can skip the key setup parts. Once you have the device configured as you'd like, build this repo:

```sh
make build
```

Then generate an secp256k1 keypair on the card:

```sh
./bin/wallet generate
```

This will prompt you for your user PIN and admin PIN.

Once you have a key on the card, you can export its public key:


```sh
./bin/wallet pubkey
```

Similarly, you may pass data to sign, which may be encoded either as a hex or ASCII string:

```sh
./bin/wallet sign some_text
./bin/wallet sign 0x1234
```

Note that by default, the message is a pre-image and the hash type is `sha256`. However, you may pass a `--hash` flag to use `keccak256` or `none`. If you use `none`, your input data must be a 32 byte hex string.

## Using the API

Alternatively, you may export the pubkey or sign from the API. Note that the API does not expose the ability to generate a key.

```go
import (
  "github.com/alex-miller-0/openpgp-secp256k1-wallet/pkg/api"
)

// Hash `data` with keccak256 and sign
sig, err := api.Sign(data, userPin, "keccak256")

// Pass pre-hashed data to be signed
// `data` must be 32 bytes in this case!
sig, err = api.SignPrehashed(data, userPin)

// Export the uncompressed pubkey
pubkey, err := api.GetPub(userPin)
```