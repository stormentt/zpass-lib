package crypto

import (
	"encoding/binary"

	"github.com/pkg/errors"
	"golang.org/x/crypto/salsa20/salsa"
)

type SalsaNonce [16]byte

func (n *SalsaNonce) Incr(count int) {
	counter := binary.LittleEndian.Uint64(n[8:])
	counter += uint64(count)
	binary.LittleEndian.PutUint64(n[8:], counter)
}

func salsaSubs(key []byte, nonce []byte, blockCount uint64) ([32]byte, SalsaNonce, error) {

	if len(key) != 32 {
		return [32]byte{}, SalsaNonce{}, errors.New("invalid key length")
	}

	if len(nonce) != 24 {
		return [32]byte{}, SalsaNonce{}, errors.New("invalid nonce length")
	}

	var fixedKey [32]byte
	copy(fixedKey[:], key)

	var hNonce [16]byte
	copy(hNonce[:], nonce[:16])

	var subNonce [16]byte
	copy(subNonce[:], nonce[16:])

	var subKey [32]byte
	salsa.HSalsa20(&subKey, &hNonce, &fixedKey, &salsa.Sigma)

	binary.LittleEndian.PutUint64(subNonce[8:], blockCount)

	return subKey, SalsaNonce(subNonce), nil
}
