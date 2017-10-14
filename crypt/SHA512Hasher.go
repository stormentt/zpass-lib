package crypt

import (
	"crypto/hmac"
	"crypto/sha512"
	"github.com/stormentt/zpass-lib/random"
)

type Sha512Hasher struct {
	SymmetricHasher
}

func (h Sha512Hasher) Digest(message []byte) []byte {
	mac := hmac.New(sha512.New, h.Key)
	mac.Write(message)
	hmac := mac.Sum(nil)
	return hmac
}

func (h Sha512Hasher) Verify(message, testMac []byte) bool {
	expectedMAC := h.Digest(message)
	return hmac.Equal(testMac, expectedMAC)
}

func (h Sha512Hasher) GenKey() ([]byte, error) {
	key, err := random.Bytes(sha512.BlockSize)
	return key, err
}
