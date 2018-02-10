package crypto

import (
	"crypto/hmac"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/salsa20/salsa"
)

type SalsaReader struct {
	backing   io.ReadSeeker
	Integrous bool

	sKey   [EncKeySize]byte
	sNonce SalsaNonce

	position uint64
}

func NewSalsaReader(encKey EncryptionKey, intKey IntegrityKey, backing io.ReadSeeker) (*SalsaReader, error) {
	if len(encKey) != EncKeySize {
		return nil, EncKeyBadSizeError{len(encKey)}
	}

	if len(intKey) != IntKeySize {
		return nil, IntKeyBadSizeError{len(intKey)}
	}

	hash, _ := intKey.NewHash()

	testHash := make([]byte, IntHashSize)
	_, err := backing.Read(testHash)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, EncNonceSize)
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
		return nil, MACMismatchError{testMAC: testHash, calcMAC: calcHash}
	}

	_, err = backing.Seek(MsgOverhead, 0)
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
		return 0, UnintegrousReadError{}
	}

	positionOffset := sr.position % EncBlockSize
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
	sr.sNonce.Set(sr.position / EncBlockSize)
	return n - int(positionOffset), nil
}

func (sr *SalsaReader) Seek(offset int64, whence int) (int64, error) {
	if !sr.Integrous {
		return 0, UnintegrousReadError{}
	}

	switch whence {
	case io.SeekStart:
		n, err := sr.backing.Seek(MsgOverhead+offset, whence)
		if err != nil {
			return n, err
		}

		sr.position = uint64(n) - MsgOverhead
		sr.sNonce.Set((uint64(n) - MsgOverhead) / EncBlockSize)
	case io.SeekCurrent:
		n, err := sr.backing.Seek(offset, whence)
		if err != nil {
			return n, err
		}

		if n < MsgOverhead {
			return 0, SoughtBehindError{}
		}

		sr.position = uint64(n) - MsgOverhead
		sr.sNonce.Set((uint64(n) - MsgOverhead) / EncBlockSize)
	case io.SeekEnd:
		n, err := sr.backing.Seek(offset, whence)
		if err != nil {
			return n, err
		}

		if n < MsgOverhead {
			return 0, SoughtBehindError{}
		}

		sr.position = uint64(n) - MsgOverhead
		sr.sNonce.Set((uint64(n) - MsgOverhead) / EncBlockSize)
	}

	return 0, errors.New("seek: invalid whence value")
}

func (sr *SalsaReader) WriteTo(w io.Writer) (int64, error) {
	if !sr.Integrous {
		return 0, UnintegrousReadError{}
	}

	data := make([]byte, FileChunkSize)
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
