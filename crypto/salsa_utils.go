package crypto

import (
	"encoding/binary"

	"golang.org/x/crypto/salsa20/salsa"
)

type SalsaNonce [16]byte

func (n *SalsaNonce) Incr(count int) {
	counter := binary.LittleEndian.Uint64(n[8:])
	counter += uint64(count)
	binary.LittleEndian.PutUint64(n[8:], counter)
}

func (n *SalsaNonce) Decr(count int) {
	counter := binary.LittleEndian.Uint64(n[8:])
	counter -= uint64(count)
	binary.LittleEndian.PutUint64(n[8:], counter)
}

func (n *SalsaNonce) Set(count uint64) {
	binary.LittleEndian.PutUint64(n[8:], count)
}

func (n *SalsaNonce) Bytes() *[16]byte {
	return (*[16]byte)(n)
}

func (n *SalsaNonce) Counter() uint64 {
	u := binary.LittleEndian.Uint64(n[8:])
	return u
}

func salsaSubs(key []byte, nonce []byte, blockCount uint64) ([EncKeySize]byte, SalsaNonce, error) {

	if len(key) != EncKeySize {
		return [EncKeySize]byte{}, SalsaNonce{}, EncKeyBadSizeError{len(key)}
	}

	if len(nonce) != 24 {
		return [EncKeySize]byte{}, SalsaNonce{}, EncNonceBadSizeError{len(nonce)}
	}

	var fixedKey [EncKeySize]byte
	copy(fixedKey[:], key)

	var hNonce [16]byte
	copy(hNonce[:], nonce[:16])

	var subNonce [16]byte
	copy(subNonce[:], nonce[16:])

	var subKey [EncKeySize]byte
	salsa.HSalsa20(&subKey, &hNonce, &fixedKey, &salsa.Sigma)

	binary.LittleEndian.PutUint64(subNonce[8:], blockCount)

	return subKey, SalsaNonce(subNonce), nil
}
