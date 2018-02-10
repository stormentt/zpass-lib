package crypto

import (
	"crypto/hmac"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/salsa20/salsa"
)

// SalsaReader decrypts an io.ReadSeeker
type SalsaReader struct {
	backing io.ReadSeeker

	// Integrous is true if the reader's MAC was valid, false otherwise
	Integrous bool

	sKey   [EncKeySize]byte
	sNonce SalsaNonce

	position uint64
}

// NewSalsaReader creates a new SalsaReader which will read from backing
//
// This function validates the backing's MAC and will block until the validation is finished. If the validation fails, it will return an error and block the SalsaReader from reading.
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

// Read decrypts and returns data
//
// If the SalsaReader's validation failed in NewSalsaReader, this will return an error
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

// Seek seeks to an offset in the DECRYPTED file. So seeking to position will put you at MsgOverhead in the backing stream, which is the start of the actual encrypted information.
//
// Diagram
//	                     v Seek(0,0) will put you here
// 	[MAC, Nonce, Etc ::: Actual Encrypted Data]
// 	                  ^ MsgOverhead bytes
// If the SalsaReader's validation failed in NewSalsaReader, this will return an error
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

// WriteTo decrypts the entire backing reader and writes the decrypted contents to the given writer
//
// WriteTo reads from the backing reader in FileChunkSize byte blocks
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
