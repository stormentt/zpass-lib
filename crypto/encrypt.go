package crypto

import (
	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/util/slices"
	"golang.org/x/crypto/salsa20"
)

type EncryptionKey []byte

func NewEncryptionKey() (EncryptionKey, error) {
	key, err := random.Bytes(EncKeySize)
	if err != nil {
		return nil, err
	}

	return EncryptionKey(key), nil
}

func (key EncryptionKey) Encrypt(msg []byte) ([]byte, error) {
	if len(key) != EncKeySize {
		return nil, EncKeyBadSizeError{len(key)}
	}

	nonce, err := random.Bytes(24)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(msg))

	var encKey [EncKeySize]byte
	copy(encKey[:], []byte(key))
	salsa20.XORKeyStream(ciphertext, msg, nonce, &encKey)

	nonceAndCipher := slices.Combine(nonce, ciphertext)

	return nonceAndCipher, nil
}

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
