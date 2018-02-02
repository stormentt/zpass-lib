package crypto

import (
	"bytes"
	"hash"
	"io"

	"github.com/pkg/errors"
	"github.com/stormentt/zpass-lib/random"
)

type SalsaWriter struct {
	backing io.WriteSeeker
	Closed  bool

	bufferBytes []byte
	buffer      *bytes.Buffer

	hash hash.Hash

	sKey   [32]byte
	sNonce SalsaNonce

	blockCounter int
}

func NewSalsaWriter(encKey EncryptionKey, intKey IntegrityKey, backing io.WriteSeeker) (*SalsaWriter, error) {
	if len(encKey) != EncryptionKeyLength {
		return nil, errors.New("EncryptionKey: invalid key size, must be 32")
	}

	if len(intKey) != IntegrityKeyLength {
		return nil, errors.New("IntegrityKey: invalid key size, must be 64")
	}

	blank := make([]byte, 64)
	_, err := backing.Write(blank)
	if err != nil {
		return nil, err
	}

	nonce, err := random.Bytes(EncryptionNonceSize)
	if err != nil {
		return nil, err
	}

	hash, err := intKey.NewHash()
	if err != nil {
		return nil, err
	}
	hash.Write(nonce)

	_, err := backing.Write(nonce)
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
	sw.buffer = sw.bufferBacking

	return &sw
}

func (sw *SalsaWriter) Write(p []byte) (int, error) {
	if sw.Closed {
		return 0, errors.New("salsawriter already closed")
	}

	var total int

	pLen := len(p)
	bLen := sw.buffer.Len()

	if bLen > 0 && pLen+bLen >= 64 {
		if pLen > 0 {
			n, _ := sw.buffer.Write(p[:64-bLen])
			p = p[n:]
			pLen = len(p)
			bLen = sw.buffer.Len()
		}

		sw.hash.Write(sw.bufferBytes[:bLen])
		n, err := io.Copy(sw.backing, sw.buffer)
		total += int(n)
		if err != nil {
			return total, errors.WithStack(err)
		}
	}

	if pLen > 0 {
		pBlocks := pLen / 64
		pRemainder := pLen - (pBlocks * 64)
		pFullLen := pLen - pRemainder

		sw.hash.Write(p[:pFullLen])
		n, err := sw.backing.Write(p[:pFullLen])
		total += int(n)
		if err != nil {
			return total, errors.WithStack(err)
		}

		if pRemainder > 0 {
			n, _ := sw.buffer.Write(p[pFullLen:])
		}
	}

	totalBlocks := total / 64
	sw.sNonce.Incr(totalBlocks)
	sw.blockCounter += totalBlocks
	return total, nil
}

func (sw *SalsaWriter) Close() error {
	if sw.Closed {
		return errors.New("salsawriter already Closed")
	}

	sw.hash.Write(sw.bufferBytes[:sw.buffer.Len])
	n, err := io.Copy(sw.backing, sw.buffer)
	if err != nil {
		return err
	}

	_, err := sw.backing.Seek(0, 0)
	if err != nil {
		return err
	}

	sw.backing.Write(sw.hash.Sum(nil))

	sw.Closed = true
	return nil
}

func (sw *SalsaWriter) ReadFrom(r io.Reader) (int64, error) {
	data := make([]byte, ChunkSize)
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
