package XSalsa20

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-lib/crypt/SHA512"
	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/util/slices"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/scrypt"
)

const (
	KeySize       = 64
	FileChunkSize = 128 * 1024
)

// Package XSalsa20 provides a crypter for encrypting/decrypting data with XSalsa20.
// We use SHA512-HMAC with a seperate key to provide messenge integrity

type XSalsa20Crypter struct {
	Key []byte //The first 256 bytes of this key are used as the encryption key. The second 256 (or more, if more are provided) are used as the signing key.
}

func Create(key []byte) (*XSalsa20Crypter, error) {
	var c XSalsa20Crypter
	if key == nil {
		err := c.GenKey()
		if err != nil {
			return nil, errors.Wrap(err, "Error initializing crypter")
		}
	} else {
		if len(key) < KeySize {
			err := errors.New("Key size incorrect")
			log.WithFields(log.Fields{
				"error":    err,
				"crypter":  "XSalsa20",
				"size":     len(key),
				"expected": KeySize,
			}).Debug("Error creating crypter")
			return nil, err
		}
		c.Key = key
	}
	return &c, nil
}

func (c *XSalsa20Crypter) Encrypt(message []byte) ([]byte, error) {
	var encKey [32]byte
	copy(encKey[:], c.Key[:32])

	signKey := c.Key[32:]

	nonce, err := random.Bytes(24)
	if err != nil {
		return nil, errors.Wrap(err, "Error generating nonce")
	}

	cipherText := make([]byte, len(message))
	salsa20.XORKeyStream(cipherText[:], message[:], nonce, &encKey)

	nonceAndCipher := slices.Combine(nonce, cipherText)

	hasher, err := SHA512.Create(signKey)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to hash message")
	}
	mac := hasher.Digest(nonceAndCipher)

	final := slices.Combine(mac, nonceAndCipher)
	return final, nil
}

func (c *XSalsa20Crypter) Decrypt(message []byte) ([]byte, error) {
	var encKey [32]byte
	copy(encKey[:], c.Key[:32])

	signKey := c.Key[32:]

	testMac := message[:64]
	nonceAndCipher := message[64:]

	hasher, err := SHA512.Create(signKey)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to verify message")
	}

	valid := hasher.Verify(nonceAndCipher, testMac)

	if !valid {
		log.WithFields(log.Fields{
			"error":   "Invalid signature",
			"crypter": "XSalsa20",
			"hasher":  "SHA512",
		}).Debug("Invalid signature")
		return nil, errors.New("Invalid signature")
	}

	nonce := nonceAndCipher[:24]
	cipherText := nonceAndCipher[24:]

	plaintext := make([]byte, len(cipherText))

	salsa20.XORKeyStream(plaintext[:], cipherText[:], nonce, &encKey)

	return plaintext, nil
}

func (c *XSalsa20Crypter) GenKey() (err error) {
	c.Key, err = random.Bytes(KeySize)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"crypter": "XSalsa20",
		}).Debug("Error generating key")
		return errors.Wrap(err, "Error generating key")
	}
	return nil
}

func (c *XSalsa20Crypter) DeriveKey(password []byte) ([]byte, error) {
	salt, err := random.Bytes(32)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to derive key")
	}

	derived, err := scrypt.Key(password, salt, 1<<16, 8, 1, KeySize)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"salt":     salt,
			"password": password,
			"crypter":  "XSalsa20",
		}).Debug("Error deriving key")
		return nil, errors.Wrap(err, "Error deriving key")
	}

	c.Key = derived

	return salt, nil
}

func (c *XSalsa20Crypter) CalcKey(password, salt []byte) (err error) {
	c.Key, err = scrypt.Key(password, salt, 1<<16, 8, 1, KeySize)
	if err != nil {
		log.WithFields(log.Fields{
			"crypter":  "XSalsa20",
			"error":    err,
			"password": password,
			"salt":     salt,
		}).Debug("Error calculating key")
		return errors.Wrap(err, "Error calculating key")
	}
	return nil
}

// EncryptFile encrypts inFile and writes to outFile
// outFile will be truncated if it exists.
// As we're encrypting, we also calculate an HMAC using the encrypted output. We write this HMAC to the start of the file
func (c *XSalsa20Crypter) EncryptFile(inFile, outFile string) (err error) {
	in, err := os.Open(inFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err,
			"inFile": inFile,
		}).Debug("Unable to encrypt file")
		return errors.Wrap(err, "Unable to encrypt file")
	}
	defer in.Close()

	out, err := os.Create(outFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"outFile": outFile,
		}).Debug("Unable to encrypt file")
		return errors.Wrap(err, "Unable to encrypt file")
	}
	defer out.Close()

	// I'm giving 4 bytes to be used as a counter because that gives us 160 bits for random data & 32 bits for file size. 32 bits of file size gives us a maximum safe encryption limit of 4GiB.
	nonce, err := random.Bytes(20)
	var counter uint32
	counterBytes := make([]byte, 4)

	var encKey [32]byte
	copy(encKey[:], c.Key[:32])
	authKey := c.Key[32:]

	mac := hmac.New(sha512.New, authKey)
	mac.Write(nonce)

	// Leave space for the HMAC
	blank := make([]byte, 64)
	_, err = out.Write(blank)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"outFile": outFile,
		}).Debug("Error writing space for MAC")
		return errors.Wrap(err, "Error encrypting file")
	}

	// Write the Nonce
	_, err = out.Write(nonce)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"outFile": outFile,
		}).Debug("Error writing nonce")
		return errors.Wrap(err, "Error encrypting file")
	}

	data := make([]byte, FileChunkSize)
	for {
		n, err := in.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(log.Fields{
				"error":  err,
				"inFile": inFile,
			}).Debug("Error while reading file")
			return err
		}
		counter += uint32(n)
		binary.LittleEndian.PutUint32(counterBytes, counter)
		data = data[:n]

		combinedNonce := slices.Combine(nonce, counterBytes)

		// The order of these operations is very important.
		// We MUST calculate the HMAC of the encrypted data, NOT the HMAC of the plaintext. NEVER do any other order.
		salsa20.XORKeyStream(data, data, combinedNonce, &encKey)
		mac.Write(data)

		_, err = out.Write(data)
		if err != nil {
			log.WithFields(log.Fields{
				"error":   err,
				"inFile":  inFile,
				"outFile": outFile,
			}).Debug("Error writing encrypted file")
			return errors.Wrap(err, "Error writing encrypted file")
		}
	}

	// Write the MAC to the start of the file, in the placeholder we left
	hash := mac.Sum(nil)
	out.Seek(0, 0)
	_, err = out.Write(hash)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"inFile":  inFile,
			"outFile": outFile,
		}).Debug("Error writing encrypted file hash")
		return errors.Wrap(err, "Unable to write encrypted file")
	}

	return nil
}

// DecryptFile decrypts inFile and writes the result to outFile
// outFile will be truncated if it already exists
// Before we do any decription, we check the HMAC of the encrypted file. We refuse to decrypt if there's a problem.
func (c *XSalsa20Crypter) DecryptFile(inFile, outFile string) (err error) {
	in, err := os.Open(inFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err,
			"inFile": inFile,
		}).Debug("Unable to decrypt file")
		return errors.Wrap(err, "Unable to decrypt file")
	}
	defer in.Close()

	out, err := os.Create(outFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"outFile": outFile,
		}).Debug("Unable to decrypt file")
		return errors.Wrap(err, "Unable to decrypt file")
	}
	defer out.Close()

	testMac := make([]byte, 64)
	_, err = in.Read(testMac)
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"inFile":  inFile,
			"testMAC": testMac,
		}).Debug("Unable to read file for decryption")
		return errors.Wrap(err, "Unable to decrypt file")
	}

	nonce := make([]byte, 20)
	_, err = in.Read(nonce)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err,
			"inFile": inFile,
		}).Debug("Unable to read file for decryption")
		return errors.Wrap(err, "Unable to decrypt file")
	}

	// We MUST check the integrity of the data before decrypting.
	// Anything else is terrifying.
	authKey := c.Key[32:]
	mac := hmac.New(sha512.New, authKey)
	mac.Write(nonce)
	data := make([]byte, FileChunkSize)
	for {
		n, err := in.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(log.Fields{
				"error":  err,
				"inFile": inFile,
			}).Debug("Error while reading file")
			return err
		}

		data = data[:n]
		mac.Write(data)
	}

	// Time to compare the HMACs
	expectedMac := mac.Sum(nil)
	if !hmac.Equal(testMac, expectedMac) {
		log.WithFields(log.Fields{
			"error":       "Invalid HMAC",
			"testMac":     testMac,
			"expectedMac": expectedMac,
		}).Debug("Unable to decrypt file")
		return errors.New("HMAC Mismatch")
	}

	// Now that we know the data hasn't been tampered with, we can actually start decrypting.
	in.Seek((64 + 20), 0)

	var counter uint32
	counterBytes := make([]byte, 4)

	var encKey [32]byte
	copy(encKey[:], c.Key[:32])

	for {
		n, err := in.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(log.Fields{
				"error":  err,
				"inFile": inFile,
			}).Debug("Error while reading file")
			return err
		}
		counter += uint32(n)
		binary.LittleEndian.PutUint32(counterBytes, counter)
		data = data[:n]

		combinedNonce := slices.Combine(nonce, counterBytes)
		salsa20.XORKeyStream(data, data, combinedNonce, &encKey)

		_, err = out.Write(data)
		if err != nil {
			log.WithFields(log.Fields{
				"error":   err,
				"inFile":  inFile,
				"outFile": outFile,
			}).Debug("Error writing encrypted file")
			return errors.Wrap(err, "Error writing encrypted file")
		}
	}

	return nil
}
