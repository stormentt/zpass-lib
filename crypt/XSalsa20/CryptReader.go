package XSalsa20

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-lib/streams"
	"golang.org/x/crypto/salsa20/salsa"
)

type CryptReader struct {
	nonce      []byte
	backing    io.ReadSeeker
	valid      bool
	checked    bool
	key        []byte
	position   uint64 // position from the start of the actual stream data
	salsaKey   [32]byte
	salsaNonce [8]byte
}

func NewCryptReader(backing io.ReadSeeker, key []byte) *CryptReader {
	cr := new(CryptReader)
	cr.backing = backing
	cr.key = key
	cr.nonce = make([]byte, 24)

	return cr
}

func (c *CryptReader) initializeSalsa() {
	// oh boy oh man, i'm gonna fuck this up
	var encKey [32]byte
	copy(encKey[:], c.key[:32])

	var hNonce [16]byte
	copy(hNonce[:], c.nonce[:16])

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[16:])

	var subKey [32]byte
	salsa.HSalsa20(&subKey, &hNonce, &encKey, &salsa.Sigma)
	copy(c.salsaKey[:], subKey[:])
	copy(c.salsaNonce[:], subNonce[:8])
}

func (c *CryptReader) Seek(offset int64, whence int) (int64, error) {
	pos, err := c.backing.Seek(offset, whence)
	c.position = uint64(pos)
	return pos, err
}

func (c *CryptReader) Initialize() error {
	_, err := c.backing.Seek(0, 0)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err,
			"cipher": "XSalsa20",
		}).Debug("Error seeking to start of CryptReader backing")
		return errors.Wrap(err, "Unable to initialize CryptReader")
	}

	authKey := c.key[32:]

	testMAC := make([]byte, 64)
	n, err := c.backing.Read(testMAC)
	if n != 64 {
		log.WithFields(log.Fields{
			"n":   n,
			"err": err,
		}).Debug("Unable to read testMAC for CryptReader")
		if err != nil {
			return err
		} else {
			return &streams.StreamIncompleteError{}
		}
	}

	nonce := make([]byte, 24)
	n, err = c.backing.Read(nonce)
	if n != 24 {
		log.WithFields(log.Fields{
			"n":   n,
			"err": err,
		}).Debug("Unable to read nonce for CryptReader")
		if err != nil {
			return err
		} else {
			return &streams.StreamIncompleteError{}
		}
	}
	copy(c.nonce, nonce)

	mac := hmac.New(sha512.New, authKey)
	mac.Write(nonce)
	_, err = io.Copy(mac, c.backing)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Debug("Error calculating hash of stream")
		return err
	}
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(testMAC, expectedMAC) {
		return &streams.InvalidStreamError{}
	}

	_, err = c.backing.Seek(88, 0) // 64byte hash + 24byte nonce
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Debug("Unable to seek CryptReader after checking HMAC")
		return errors.Wrap(err, "Unable to initialize CryptReader")
	}
	c.valid = true
	c.checked = true

	c.initializeSalsa()
	return nil
}

func (c *CryptReader) Read(d []byte) (int, error) {
	if !c.checked {
		return 0, &streams.UncheckedError{}
	}

	if !c.valid {
		return 0, &streams.InvalidStreamError{}
	}

	tmp := make([]byte, len(d))

	n, err := c.backing.Read(tmp)
	if err != nil {
		log.WithFields(log.Fields{
			"n":     n,
			"error": err,
		}).Debug("Error decrypting CryptStream")
		return 0, errors.Wrap(err, "Error decrypting stream")
	}

	var positionBytes [8]byte
	binary.LittleEndian.PutUint64(positionBytes[:], c.position)

	var nonceBytes [16]byte
	copy(nonceBytes[:], c.salsaNonce[:])
	copy(nonceBytes[8:], positionBytes[:])

	fmt.Printf("nonce: %X\n", nonceBytes)
	salsa.XORKeyStream(tmp, tmp, &nonceBytes, &c.salsaKey)

	c.position += uint64(n)

	copy(d, tmp)

	return n, nil
}

func (r *CryptReader) WriteTo(w io.Writer) (int, error) {
	data := make([]byte, FileChunkSize)
	total := 0
	for {
		n, err := r.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			return total, err
		}
		written, err := w.Write(data[:n])
		if err != nil {
			return total, err
		}
		total += written
	}
	return total, nil
}
