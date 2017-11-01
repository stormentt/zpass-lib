package ChaCha20Poly1305

// Package ChaCha20Poly1305 provides a crypter for encrypting/decrypting data with ChaCha20-Poly1305
// ChaCha20-Poly1305 loses message authenticity if nonces are repeated.
// 12 bytes is arguably not long enough to guarantee this won't happen when generating by random bytes.
// Eventually I'll figure out how to make it use a counter instead. For now use the secretbox crypter
import (
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/util/slices"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// ChaCha20Crypter encrypts & decrypts data using the AEAD chacha20-poly1305
type ChaCha20Crypter struct {
	Key []byte
}

// Init creates a new ChaCha20 Crypter.
// If no key is provided it will generate one
func Create(key []byte) (*ChaCha20Crypter, error) {
	var c ChaCha20Crypter
	if key == nil {
		err := c.GenKey()
		if err != nil {
			return nil, errors.Wrap(err, "Error initializing crypter")
		}
	} else {
		if len(key) != chacha20poly1305.KeySize {
			err := errors.New("Key size incorrect")
			log.WithFields(log.Fields{
				"error":    err,
				"crypter":  "ChaCha20-Poly1305",
				"size":     len(key),
				"expected": chacha20poly1305.KeySize,
			}).Debug("Error creating crypter")
			return nil, err
		}
		c.Key = key
	}
	return &c, nil
}

// Encrypt encrypts plaintext with chacha20-poly1305 and returns the encrypted data
func (c *ChaCha20Crypter) Encrypt(plaintext []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(c.Key)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"crypter": "ChaCha20-Poly1305",
			"key":     c.Key,
		}).Debug("Error initializing cipher")
		return nil, errors.Wrap(err, "Error initializing cipher")
	}

	nonce, err := random.Bytes(chacha20poly1305.NonceSize)
	if err != nil {
		return nil, errors.Wrap(err, "Error generating nonce")
	}

	ciphertext := cipher.Seal(nil, nonce, plaintext, nil)
	return slices.Combine(nonce, ciphertext), nil
}

// Decrypt decrypts the ciphertext and returns the decrypted data
func (c *ChaCha20Crypter) Decrypt(message []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(c.Key)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"crypter": "ChaCha20-Poly1305",
			"key":     c.Key,
		}).Debug("Error initializing cipher")
		return nil, err
	}

	nonce := message[:chacha20poly1305.NonceSize]
	cipherText := message[chacha20poly1305.NonceSize:]

	plainText, err := cipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"error":      err,
			"nonce":      nonce,
			"cipherText": cipherText,
			"key":        c.Key,
		}).Debug("Error decrypting message")
		return nil, errors.Wrap(err, "Error decrypting message")
	}
	return plainText, nil
}

func (c *ChaCha20Crypter) GenKey() (err error) {
	c.Key, err = random.Bytes(chacha20poly1305.KeySize)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"crypter": "ChaCha20-Poly1305",
		}).Debug("Error generating key")
		return errors.Wrap(err, "Error generating key")
	}
	return nil
}

func (c *ChaCha20Crypter) DeriveKey(password []byte) ([]byte, error) {
	salt, err := random.Bytes(32)
	if err != nil {
		return nil, err
	}

	derived, err := scrypt.Key(password, salt, 1<<16, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"salt":     salt,
			"password": password,
			"crypter":  "ChaCha20-Poly1305",
		}).Debug("Error deriving key")
		return nil, errors.Wrap(err, "Error deriving key")
	}

	c.Key = derived

	return salt, nil
}

func (c *ChaCha20Crypter) CalcKey(password, salt []byte) (err error) {
	c.Key, err = scrypt.Key(password, salt, 1<<16, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		log.WithFields(log.Fields{
			"crypter":  "ChaCha20-Poly1305",
			"error":    err,
			"password": password,
			"salt":     salt,
		}).Debug("Error calculating key")
		return errors.Wrap(err, "Error calculating key")
	}
	return nil
}

func (c *ChaCha20Crypter) EncryptFile(inFile, outFile string) (err error) {
	return errors.New("Not implemented")
}
func (c *ChaCha20Crypter) DecryptFile(inFile, outFile string) (err error) {
	return errors.New("Not implemented")
}
