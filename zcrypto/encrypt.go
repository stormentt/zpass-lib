package zcrypto

import (
	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/util/slices"
	"golang.org/x/crypto/salsa20"
)

// EncryptionKey must be EncKeySize bytes long.
type EncryptionKey []byte

// NewEncryptionKey generates a new random encryption key
func NewEncryptionKey() (EncryptionKey, error) {
	key := random.Bytes(EncKeySize)
	return EncryptionKey(key), nil
}

// Encrypt encrypts a message
//
// Important! Encrypt does NOT calculate a MAC. If you want to use Encrypt, make sure to include a MAC or you're just asking for trouble.
//
// The returned byte slice is Nonce + Ciphertext
func (key EncryptionKey) Encrypt(msg []byte) ([]byte, error) {
	if len(key) != EncKeySize {
		return nil, EncKeyBadSizeError{len(key)}
	}

	nonce := random.Bytes(EncNonceSize)

	ciphertext := make([]byte, len(msg))

	var encKey [EncKeySize]byte
	copy(encKey[:], []byte(key))
	salsa20.XORKeyStream(ciphertext, msg, nonce, &encKey)

	nonceAndCipher := slices.Combine(nonce, ciphertext)

	return nonceAndCipher, nil
}

// Decrypt decrypts a message
//
// Important! Decrypt does NOT validate a MAC. If you want to use Decrypt, make sure to validate a MAC beforehand. Failure to do so will result in decapitation.
func (key EncryptionKey) Decrypt(msg []byte) ([]byte, error) {
	if len(key) != EncKeySize {
		return nil, EncKeyBadSizeError{len(key)}
	}

	if len(msg) < EncNonceSize {
		return nil, MsgTooShortError{wanted: EncNonceSize, size: len(msg)}
	}

	nonce := msg[:EncNonceSize]
	ciphertext := msg[EncNonceSize:]

	plaintext := make([]byte, len(ciphertext))

	var encKey [EncKeySize]byte
	copy(encKey[:], []byte(key))
	salsa20.XORKeyStream(plaintext, ciphertext, nonce, &encKey)

	return plaintext, nil
}
