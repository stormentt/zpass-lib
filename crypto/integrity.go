package crypto

import (
	"crypto/hmac"

	"github.com/stormentt/zpass-lib/random"
	"golang.org/x/crypto/blake2b"
)

type IntegrityKey []byte

func NewIntegrityKey() (IntegrityKey, error) {
	key, err := random.Bytes(64)
	if err != nil {
		return nil, err
	}

	return IntegrityKey(key), nil
}

func (key IntegrityKey) Sign(msg []byte) ([]byte, error) {
	blake, err := blake2b.New512(key)
	if err != nil {
		return nil, err
	}

	_, _ = blake.Write(msg)
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
	blake, err := blake2b.New512(key)
	if err != nil {
		return nil, err
	}

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
