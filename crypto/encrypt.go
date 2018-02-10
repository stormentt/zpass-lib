package crypto

import (
	"github.com/pkg/errors"
	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/util/slices"
	"golang.org/x/crypto/salsa20"
)

const EncryptionKeyLength = 32
const EncryptionNonceLength = 24

type EncryptionKey []byte

func NewEncryptionKey() (EncryptionKey, error) {
	key, err := random.Bytes(EncryptionKeyLength)
	if err != nil {
		return nil, err
	}

	return EncryptionKey(key), nil
}

func (key EncryptionKey) Encrypt(msg []byte) ([]byte, error) {
	if len(key) != EncryptionKeyLength {
		return nil, errors.New("EncryptionKey: invalid key size, must be 32")
	}

	nonce, err := random.Bytes(24)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(msg))

	var encKey [EncryptionKeyLength]byte
	copy(encKey[:], []byte(key))
	salsa20.XORKeyStream(ciphertext, msg, nonce, &encKey)

	nonceAndCipher := slices.Combine(nonce, ciphertext)

	return nonceAndCipher, nil
}

func (key EncryptionKey) Decrypt(msg []byte) ([]byte, error) {
	if len(key) != EncryptionKeyLength {
		return nil, errors.New("EncryptionKey: invalid key size, must be EncryptionKeyLength")
	}

	if len(msg) <= 24 {
		return nil, errors.New("EncryptionKey: can't decrypt, msg length must be at least 24")
	}

	nonce := msg[:24]
	ciphertext := msg[24:]

	plaintext := make([]byte, len(ciphertext))

	var encKey [EncryptionKeyLength]byte
	copy(encKey[:], []byte(key))
	salsa20.XORKeyStream(plaintext, ciphertext, nonce, &encKey)

	return plaintext, nil
}
