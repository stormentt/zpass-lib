package zcrypto

import (
	"bytes"
	"hash"
	"io"

	"github.com/pkg/errors"
	"github.com/stormentt/zpass-lib/random"
	"golang.org/x/crypto/salsa20/salsa"
)

// SalsaWriter encrypts data and writes it to an io.WriteSeeker
type SalsaWriter struct {
	backing io.WriteSeeker

	// Closed is true if the stream is closed & the MAC has been written
	Closed bool

	bufferBytes []byte
	buffer      *bytes.Buffer

	hash hash.Hash

	sKey   [EncKeySize]byte
	sNonce SalsaNonce
}

// NewSalsaWriter creates a new SalsaWriter that will write to backing
//
// This function leaves a IntHashSize byte block at the start of the backing stream, to hold the position of the MAC once its been calculated.
func NewSalsaWriter(encKey EncryptionKey, intKey IntegrityKey, backing io.WriteSeeker) (*SalsaWriter, error) {
	if len(encKey) != EncKeySize {
		return nil, EncKeyBadSizeError{len(encKey)}
	}

	if len(intKey) != IntKeySize {
		return nil, IntKeyBadSizeError{len(encKey)}
	}

	blank := make([]byte, IntHashSize)
	_, err := backing.Write(blank)
	if err != nil {
		return nil, err
	}

	nonce := random.Bytes(EncNonceSize)

	hash, err := intKey.NewHash()
	if err != nil {
		return nil, err
	}
	hash.Write(nonce)

	_, err = backing.Write(nonce)
	if err != nil {
		return nil, err
	}

	sKey, sNonce, err := salsaSubs(encKey, nonce, 0)
	if err != nil {
		return nil, err
	}

	sw := SalsaWriter{
		backing: backing,
		sKey:    sKey,
		sNonce:  sNonce,
		hash:    hash,
	}
	sw.buffer = bytes.NewBuffer(sw.bufferBytes)

	return &sw, nil
}

// encryptBuffer encrypts the SalsaWriter's internal buffer
func (sw *SalsaWriter) encryptBuffer() {
	buffBytes := sw.buffer.Bytes()

	salsa.XORKeyStream(buffBytes, buffBytes, sw.sNonce.Bytes(), &sw.sKey)
	sw.hash.Write(buffBytes)
	sw.sNonce.Incr(len(buffBytes) / EncBlockSize)
}

// flushBuffer writes the SalsaWriter's internal buffer to the backing
func (sw *SalsaWriter) flushBuffer() (int64, error) {
	return io.Copy(sw.backing, sw.buffer)
}

// passEncrypted encrypts a byte slice and writes it to the backing
func (sw *SalsaWriter) passEncrypted(p []byte) (int, error) {
	tmp := make([]byte, len(p))
	salsa.XORKeyStream(tmp, p, sw.sNonce.Bytes(), &sw.sKey)
	sw.hash.Write(tmp)
	sw.sNonce.Incr(len(tmp) / EncBlockSize)
	return sw.backing.Write(tmp)
}

// Write encrypts a byte slice and writes it to the backing
//
// XSalsa20 operates on 64 byte blocks, so to keep everything consistent we only write full 64 byte blocks. To manage this, we keep an internal buffer. When writing new data to the SalsaWriter we check the buffer size. If the buffer can be filled with bytes from p, we do that first, encrypt the buffer, and then flush the buffer. After that, we encrypt & write as many full blocks of p as we can, and store the leftovers in the internal buffer.
func (sw *SalsaWriter) Write(p []byte) (int, error) {
	if sw.Closed {
		return 0, SalsaWriterClosedError{}
	}

	var total int

	pLen := len(p)
	bLen := sw.buffer.Len()

	if bLen > 0 && pLen+bLen >= EncBlockSize {
		if pLen > 0 {
			n, _ := sw.buffer.Write(p[:EncBlockSize-bLen])
			p = p[n:]
			pLen = len(p)
			bLen = sw.buffer.Len()
		}

		sw.encryptBuffer()

		n, err := sw.flushBuffer()
		total += int(n)
		if err != nil {
			return total, errors.WithStack(err)
		}

	}

	if pLen > 0 {
		pBlocks := pLen / EncBlockSize
		pRemainder := pLen - (pBlocks * EncBlockSize)
		pFullLen := pLen - pRemainder

		n, err := sw.passEncrypted(p[:pFullLen])
		total += int(n)
		if err != nil {
			return total, errors.WithStack(err)
		}

		if pRemainder > 0 {
			sw.buffer.Write(p[pFullLen:])
		}
	}

	return total, nil
}

// Close encrypts the remainder of the internal buffer & flushes it to the backing, then calculates the MAC of the entire backing and writes it to the start, in the placeholder NewSalsaWriter left earlier.
func (sw *SalsaWriter) Close() error {
	if sw.Closed {
		return SalsaWriterClosedError{}
	}

	sw.encryptBuffer()
	_, err := sw.flushBuffer()
	if err != nil {
		return err
	}

	_, err = sw.backing.Seek(0, 0)
	if err != nil {
		return err
	}

	sw.backing.Write(sw.hash.Sum(nil))

	sw.Closed = true
	return nil
}

// ReadFrom encrypts the entirety of a reader and writes the encrypted contents to backing
//
// ReadFrom reads from the reader in FileChunkSize byte blocks
func (sw *SalsaWriter) ReadFrom(r io.Reader) (int64, error) {
	data := make([]byte, FileChunkSize)
	total := int64(0)
	for {
		n, err := r.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			return total, err
		}
		data = data[:n]
		written, err := sw.Write(data)
		if err != nil {
			return total + int64(written), err
		}
		total += int64(written)
	}
	return total, nil
}
