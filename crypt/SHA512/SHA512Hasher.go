package SHA512

import (
	"crypto/hmac"
	"crypto/sha512"
	"io"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-lib/random"
)

const (
	FileChunkSize = 128 * 1024
)

type Sha512Hasher struct {
	Key []byte
}

// Create initializes a Sha512Hasher & assigns it a key
// If no key is provided, it will generate one of appropriate size.
// Keys must be over 128 bits in length and should be randomly generated.
func Create(key []byte) (*Sha512Hasher, error) {
	var h Sha512Hasher
	if key == nil {
		_, err := h.GenKey()
		if err != nil {
			return nil, err
		}
	} else {
		// I don't want to allow any keys under 128 bit.
		if len(key) < 16 {
			err := errors.New("Key too short")
			log.WithFields(log.Fields{
				"size":   len(key),
				"error":  err,
				"hasher": "sha512-HMAC",
			}).Debug("Error creating hasher")
			return nil, err
		}

		h.Key = key
	}
	return &h, nil
}

// Digest returns the sha512-hmac of a given message using this hasher's key
func (h *Sha512Hasher) Digest(message []byte) []byte {
	mac := hmac.New(sha512.New, h.Key)
	mac.Write(message)
	hmac := mac.Sum(nil)
	return hmac
}

func (h *Sha512Hasher) DigestFile(path string) ([]byte, error) {
	in, err := os.Open(path)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"path":  path,
		}).Debug("Unable to digest file")
		return nil, errors.Wrap(err, "Unable to digest file")
	}
	defer in.Close()

	data := make([]byte, FileChunkSize)
	mac := hmac.New(sha512.New, h.Key)
	for {
		n, err := in.Read(data[:cap(data)])
		if err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(log.Fields{
				"error": err,
				"path":  path,
			}).Debug("Error digesting file")
			return nil, errors.Wrap(err, "Error digesting file")
		}

		data = data[:n]
		mac.Write(data)
	}

	result := mac.Sum(nil)
	return result, nil
}

func (h *Sha512Hasher) VerifyFile(path string, testMAC []byte) bool {
	expectedMAC, err := h.DigestFile(path)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"path":  path,
		}).Debug("Error verifying file")
		return false
	}

	return hmac.Equal(testMAC, expectedMAC)
}

// Verify a message against an HMAC
func (h *Sha512Hasher) Verify(message, testMAC []byte) bool {
	expectedMAC := h.Digest(message)
	return hmac.Equal(testMAC, expectedMAC)
}

// GenKey generates a key of appropriate length for the hasher
func (h *Sha512Hasher) GenKey() (key []byte, err error) {
	h.Key, err = random.Bytes(sha512.Size)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err,
			"hasher": "sha512-HMAC",
		}).Debug("Error generating key")
		return nil, errors.Wrap(err, "Error generating key")
	}
	return h.Key, nil
}
