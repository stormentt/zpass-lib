package crypt

import (
	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/util/slices"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

type ChaCha20Crypter struct {
	SymmetricCrypter
}

func (c ChaCha20Crypter) Encrypt(plain []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(c.Key)
	if err != nil {
		return nil, err
	}

	nonce, err := random.Bytes(chacha20poly1305.NonceSize)
	if err != nil {
		return nil, err
	}

	cipherText := cipher.Seal(nil, nonce, plain, nil)
	return slices.Combine(nonce, cipherText), nil
}

func (c ChaCha20Crypter) Decrypt(encrypted []byte) ([]byte, error) {
	//TODO: Better name for encrypted
	cipher, err := chacha20poly1305.New(c.Key)
	if err != nil {
		return nil, err
	}

	nonce := encrypted[:chacha20poly1305.NonceSize]
	cipherText := encrypted[chacha20poly1305.NonceSize:]

	plainText, err := cipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func (c ChaCha20Crypter) GenKey() ([]byte, error) {
	key, err := random.Bytes(chacha20poly1305.KeySize)
	return key, err
}

func (c ChaCha20Crypter) DeriveKey(password string) ([]byte, []byte, error) {
	salt, err := random.Bytes(32)
	if err != nil {
		return nil, nil, err
	}

	derived, err := scrypt.Key([]byte(password), salt, 1<<16, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}

	return derived, salt, nil
}

func (c ChaCha20Crypter) CalcKey(password string, salt []byte) ([]byte, error) {
	derived, err := scrypt.Key([]byte(password), salt, 1<<16, 8, 1, chacha20poly1305.KeySize)
	return derived, err
}

func (c *ChaCha20Crypter) SetKeys(private, public []byte) {
	c.Key = private
}
