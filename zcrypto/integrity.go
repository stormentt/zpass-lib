package zcrypto

import (
	"crypto/hmac"
	"hash"

	"github.com/stormentt/zpass-lib/random"
	"golang.org/x/crypto/blake2b"
)

// IntegrityKey must be IntKeySize bytes long
type IntegrityKey []byte

// NewEncryptionKey generates a new random integrity key
func NewIntegrityKey() (IntegrityKey, error) {
	key, err := random.Bytes(IntKeySize)
	if err != nil {
		return nil, err
	}

	return IntegrityKey(key), nil
}

// NewHash creates a new keyed hash.Hash object
func (key IntegrityKey) NewHash() (hash.Hash, error) {
	if len(key) != IntKeySize {
		return nil, IntKeyBadSizeError{len(key)}
	}

	return blake2b.New512(key)
}

// Sign calculates the hash of the byte slice
func (key IntegrityKey) Sign(msg []byte) ([]byte, error) {
	if len(key) != IntKeySize {
		return nil, IntKeyBadSizeError{len(key)}
	}

	blake, _ := blake2b.New512(key)

	blake.Write(msg)
	sig := blake.Sum(nil)
	return sig, nil
}

// Verify validates a message against its hash
func (key IntegrityKey) Verify(msg []byte, testSig []byte) (bool, error) {
	compSig, err := key.Sign(msg)
	if err != nil {
		return false, err
	}

	if hmac.Equal(compSig, testSig) {
		return true, nil
	} else {
		return false, nil
	}
}

// SignFile calculates the hash of a file
func (key IntegrityKey) SignFile(path string) ([]byte, error) {
	if len(key) != IntKeySize {
		return nil, IntKeyBadSizeError{len(key)}
	}

	blake, _ := blake2b.New512(key)
	return HashFile(path, blake)
}

// SignFile validates a file against its hash
func (key IntegrityKey) VerifyFile(path string, testSig []byte) (bool, error) {
	compSig, err := key.SignFile(path)
	if err != nil {
		return false, err
	}

	if hmac.Equal(compSig, testSig) {
		return true, nil
	} else {
		return false, nil
	}
}
