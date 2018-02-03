package crypto

import (
	"crypto/hmac"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/salsa20/salsa"
)

type SalsaReader struct {
	backing   io.ReadSeeker
	Integrous bool

	sKey   [32]byte
	sNonce SalsaNonce

	position uint64
}

func NewSalsaReader(encKey EncryptionKey, intKey IntegrityKey, backing io.ReadSeeker) (*SalsaReader, error) {
	if len(encKey) != EncryptionKeyLength {
		return nil, errors.New("EncryptionKey: invalid key size, must be 32")
	}

	if len(intKey) != IntegrityKeyLength {
		return nil, errors.New("IntegrityKey: invalid key size, must be 64")
	}

	hash, err := intKey.NewHash()
	if err != nil {
		return nil, err
	}

	testHash := make([]byte, 64)
	_, err = backing.Read(testHash)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 24)
	_, err = backing.Read(nonce)
	if err != nil {
		return nil, err
	}
	hash.Write(nonce)

	calcHash, err := HashReader(backing, hash)
	if err != nil {
		return nil, err
	}

	match := hmac.Equal(testHash, calcHash)
	if !match {
		return nil, fmt.Errorf("mac mismatch \n  %x \n  %x\n====================", testHash, calcHash)
	}

	_, err = backing.Seek(88, 0)
	if err != nil {
		return nil, err
	}

	sKey, sNonce, err := salsaSubs(encKey, nonce, 0)
	if err != nil {
		return nil, err
	}

	sr := SalsaReader{
		backing:   backing,
		Integrous: true,

		sKey:   sKey,
		sNonce: sNonce,
	}

	return &sr, nil
}

func (sr *SalsaReader) Read(p []byte) (int, error) {
	if !sr.Integrous {
		return 0, errors.New("mac mismatch")
	}

	positionOffset := sr.position % 64
	if positionOffset != 0 {
		sr.Seek(-int64(positionOffset), io.SeekCurrent)
	}

	tmp := make([]byte, len(p)+int(positionOffset))

	n, err := sr.backing.Read(tmp)
	if err != nil {
		return 0, err
	}

	if n == int(positionOffset) {
		return 0, io.EOF
	}

	salsa.XORKeyStream(tmp, tmp, sr.sNonce.Bytes(), &sr.sKey)
	copy(p, tmp[positionOffset:])

	sr.position += uint64(n)
	sr.sNonce.Set(sr.position / 64)
	return n - int(positionOffset), nil
}

func (sr *SalsaReader) Seek(offset int64, whence int) (int64, error) {
	if !sr.Integrous {
		return 0, errors.New("mac mismatch")
	}

	switch whence {
	case io.SeekStart:
		n, err := sr.backing.Seek(88+offset, whence)
		if err != nil {
			return n, err
		}

		sr.position = uint64(n) - 88
		sr.sNonce.Set((uint64(n) - 88) / 64)
	case io.SeekCurrent:
		n, err := sr.backing.Seek(offset, whence)
		if err != nil {
			return n, err
		}

		if n < 88 {
			return 0, errors.New("sought before start of file")
		}

		sr.position = uint64(n) - 88
		sr.sNonce.Set((uint64(n) - 88) / 64)
	case io.SeekEnd:
		n, err := sr.backing.Seek(offset, whence)
		if err != nil {
			return n, err
		}

		if n < 88 {
			return 0, errors.New("sought before start of file")
		}

		sr.position = uint64(n) - 88
		sr.sNonce.Set((uint64(n) - 88) / 64)
	}

	return 0, errors.New("invalid whence value")
}

func (sr *SalsaReader) WriteTo(w io.Writer) (int64, error) {
	if !sr.Integrous {
		return 0, errors.New("mac mismatch")
	}

	data := make([]byte, ChunkSize)
	total := int64(0)
	for {
		n, err := sr.Read(data[:cap(data)])
		if err != nil {
			if err == io.EOF {
				break
			}
			return total, err
		}
		data = data[:n]
		written, err := w.Write(data)
		if err != nil {
			return total + int64(written), err
		}
		total += int64(written)
	}

	return total, nil
}
