package XSalsa20

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/streams"
	"golang.org/x/crypto/salsa20/salsa"
)

type CryptWriter struct {
	nonce      []byte
	backing    streams.FullWriter
	key        []byte
	position   uint64
	salsaKey   [32]byte
	salsaNonce [8]byte
	mac        hash.Hash
}

func NewCryptWriter(backing streams.FullWriter, key []byte) *CryptWriter {
	cw := new(CryptWriter)
	cw.nonce, _ = random.Bytes(24)
	cw.backing = backing
	cw.key = key

	cw.backing.Seek(0, 0)
	cw.backing.Write(make([]byte, 64))
	cw.backing.Write(cw.nonce)

	cw.initializeSalsa()
	cw.mac = hmac.New(sha512.New, key[32:])
	cw.mac.Write(cw.nonce)

	return cw
}

func (c *CryptWriter) initializeSalsa() {
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

func (w *CryptWriter) Write(p []byte) (int, error) {
	tmp := make([]byte, len(p))
	copy(tmp, p)

	var positionBytes [8]byte
	binary.LittleEndian.PutUint64(positionBytes[:], w.position)

	var nonceBytes [16]byte
	copy(nonceBytes[:], w.salsaNonce[:])
	copy(nonceBytes[8:], positionBytes[:])

	fmt.Printf("nonce: %X\n", nonceBytes)
	salsa.XORKeyStream(tmp, tmp, &nonceBytes, &w.salsaKey)
	n, err := w.backing.Write(tmp)
	w.mac.Write(tmp)
	w.position += uint64(n)
	return n, err
}

func (w *CryptWriter) Close() error {
	w.backing.Seek(0, 0)
	hash := w.mac.Sum(nil)
	w.backing.Write(hash)
	w.backing.Close()
	return nil
}

func (w *CryptWriter) ReadFrom(io.Reader) (int64, error) {
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
