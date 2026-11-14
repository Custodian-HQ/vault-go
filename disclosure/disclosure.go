// Package disclosure opens what a customer approved to share with the business. It is receiver-side only: the
// browser seals, the business opens. It is written separately from custodian-device-crypto on purpose, and checked
// against the same fixtures.
package disclosure

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// Suite names, as stored with the business's disclosure key.
const (
	SuiteHybrid  = "cdv1-xwing-hkdf256-aes256gcm"
	SuiteClassic = "cdv1-x25519-hkdf256-aes256gcm"
)

const (
	commitLabel      = "cdv/v1/commit"
	commitSize       = 32
	fingerprintLabel = "cdv/v1/dkfp"
)

// ErrCommitment means the stored commitment does not match the key that opened the message.
var ErrCommitment = errors.New("disclosure: key commitment does not match")

func kemFor(suite string) (hpke.KEM, error) {
	switch suite {
	case SuiteHybrid:
		return hpke.MLKEM768X25519(), nil
	case SuiteClassic:
		return hpke.DHKEM(ecdh.X25519()), nil
	}
	return nil, fmt.Errorf("disclosure: unknown suite %q", suite)
}

// GenerateKey makes a disclosure key pair. For the hybrid suite the private key is the 32-byte seed.
func GenerateKey(suite string) (private, public []byte, err error) {
	kem, err := kemFor(suite)
	if err != nil {
		return nil, nil, err
	}
	key, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	private, err = key.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return private, key.PublicKey().Bytes(), nil
}

// Open decrypts one sealed message. The commitment is compared before anything is opened.
func Open(suite string, private, enc, info, aad, ciphertext, commit []byte) ([]byte, error) {
	kem, err := kemFor(suite)
	if err != nil {
		return nil, err
	}
	key, err := kem.NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, err
	}
	expected, err := recipient.Export(commitLabel, commitSize)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(expected, commit) != 1 {
		return nil, ErrCommitment
	}
	return recipient.Open(aad, ciphertext)
}

// Fingerprint is the fingerprint of a disclosure public key: SHA-256 over the label "cdv/v1/dkfp", the suite name and the raw
// public key, each followed by a zero byte, as 64 lowercase hexadecimal characters. Keep it in your app config and send it as
// disclosure_key_fingerprint. It is not a secret.
func Fingerprint(suite string, publicKey []byte) string {
	h := sha256.New()
	h.Write([]byte(fingerprintLabel))
	h.Write([]byte{0})
	h.Write([]byte(suite))
	h.Write([]byte{0})
	h.Write(publicKey)
	return hex.EncodeToString(h.Sum(nil))
}
