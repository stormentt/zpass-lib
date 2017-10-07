package crypt

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

type ChaCha20Crypter struct {
	SymmetricCrypter
}

func (c ChaCha20Crypter) Encrypt(plain []byte) ([]byte, []byte, error) {
	cipher, err := chacha20poly1305.New(c.Key)
	if err != nil {
		log.WithFields(log.Fields{
			"cipher": "chacha20poly1305",
			"error":  err,
		}).Error("Error encrypting text")
		return nil, nil, err
	}

	nonce := RandBytes(chacha20poly1305.NonceSize)
	if len(nonce) != chacha20poly1305.NonceSize {
		if err != nil {
			log.WithFields(log.Fields{
				"cipher": "chacha20poly1305",
				"error":  "Nonce size incorrect",
			}).Error("Error encrypting text")
			return nil, nil, err
		}
	}

	cipherText := cipher.Seal(nil, nonce, plain, nil)
	return cipherText, nonce, nil
}

func (c ChaCha20Crypter) Decrypt(cipherText, nonce []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(c.Key)
	if err != nil {
		log.WithFields(log.Fields{
			"cipher": "chacha20poly1305",
			"error":  err,
		}).Error("Error decrypting text")
		return nil, err
	}

	plainText, err := cipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"cipher": "chacha20poly1305",
			"error":  err,
		}).Error("Error decrypting text")
		return nil, err
	}
	return plainText, nil
}

func (c ChaCha20Crypter) GenKey() []byte {
	key := RandBytes(chacha20poly1305.KeySize)
	return key
}

func (c ChaCha20Crypter) DeriveKey(password string) ([]byte, []byte, error) {
	salt := RandBytes(16)
	derived, err := scrypt.Key([]byte(password), salt, 1<<16, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}

	return derived, salt, nil
}

func (c ChaCha20Crypter) CalcKey(password string, salt []byte) ([]byte, error) {
	derived, err := scrypt.Key([]byte(password), salt, 1<<16, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}

	return derived, nil
}
