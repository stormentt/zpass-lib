package zcrypto

import (
	"encoding/binary"

	"golang.org/x/crypto/salsa20/salsa"
)

// SalsaNonce is a helper type for keeping track of an XSalsa20 nonce's counter
type SalsaNonce [16]byte

// Incr increments the SalsaNonce counter by count
func (n *SalsaNonce) Incr(count int) {
	counter := binary.LittleEndian.Uint64(n[8:])
	counter += uint64(count)
	binary.LittleEndian.PutUint64(n[8:], counter)
}

// Decr decrements the SalsaNonce counter by count
func (n *SalsaNonce) Decr(count int) {
	counter := binary.LittleEndian.Uint64(n[8:])
	counter -= uint64(count)
	binary.LittleEndian.PutUint64(n[8:], counter)
}

// Set sets the SalsaNonce counter to count
func (n *SalsaNonce) Set(count uint64) {
	binary.LittleEndian.PutUint64(n[8:], count)
}

// Bytes returns a pointer to the raw SalsaNonce bytes
//
// This function returns a pointer because salsa.XORKeyStream takes a pointer
func (n *SalsaNonce) Bytes() *[16]byte {
	return (*[16]byte)(n)
}

// Counter returns the uint64 representation of the SalsaNonce's counter
func (n *SalsaNonce) Counter() uint64 {
	u := binary.LittleEndian.Uint64(n[8:])
	return u
}

func (n *SalsaNonce) Copy() SalsaNonce {
	var tmp [16]byte
	copy(tmp[:], n[:])
	return tmp
}

// salsaSubs calculates the subkey & subnonce for a key & nonce pair
func salsaSubs(key []byte, nonce []byte, blockCount uint64) ([EncKeySize]byte, SalsaNonce, error) {

	if len(key) != EncKeySize {
		return [EncKeySize]byte{}, SalsaNonce{}, EncKeyBadSizeError{len(key)}
	}

	if len(nonce) != EncNonceSize {
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
