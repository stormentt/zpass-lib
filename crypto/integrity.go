package crypto

import (
	"crypto/hmac"
	"hash"

	"github.com/stormentt/zpass-lib/random"
	"golang.org/x/crypto/blake2b"
)

type IntegrityKey []byte

func NewIntegrityKey() (IntegrityKey, error) {
	key, err := random.Bytes(IntKeySize)
	if err != nil {
		return nil, err
	}

	return IntegrityKey(key), nil
}

func (key IntegrityKey) NewHash() (hash.Hash, error) {
	if len(key) != IntKeySize {
		return nil, IntKeyBadSizeError{len(key)}
	}

	return blake2b.New512(key)
}

func (key IntegrityKey) Sign(msg []byte) ([]byte, error) {
	if len(key) != IntKeySize {
		return nil, IntKeyBadSizeError{len(key)}
	}

	blake, _ := blake2b.New512(key)

	blake.Write(msg)
	sig := blake.Sum(nil)
	return sig, nil
}

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

func (key IntegrityKey) SignFile(path string) ([]byte, error) {
	if len(key) != IntKeySize {
		return nil, IntKeyBadSizeError{len(key)}
	}

	blake, _ := blake2b.New512(key)
	return HashFile(path, blake)
}

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
