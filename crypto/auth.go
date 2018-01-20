package crypto

import (
	"github.com/pkg/errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

const (
	ChunkSize = 128 * 1024
)

type AuthPair struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	raw     []byte
}

func NewAuthPair() (AuthPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return AuthPair{}, err
	}

	return AuthPair{
		private: priv,
		public:  pub,
		raw:     priv,
	}, nil
}

func AuthPairFromBytes(b []byte) (AuthPair, error) {
	pair := AuthPair{}
	pair.raw = make([]byte, len(b))
	copy(pair.raw, b[:])

	if len(b) == ed25519.PrivateKeySize {
		pair.private = ed25519.PrivateKey(pair.raw)
		pair.public = ed25519.PublicKey(pair.raw[32:])
	} else if len(b) == ed25519.PublicKeySize {
		pair.public = ed25519.PublicKey(pair.raw)
	} else {
		return AuthPair{}, errors.New("AuthPair: invalid []byte size")
	}

	return pair, nil
}

func (pair AuthPair) Bytes() []byte {
	if pair.private != nil {
		return pair.private
	}

	return pair.public
}

func (pair AuthPair) Sign(msg []byte) ([]byte, error) {
	if pair.private == nil {
		return nil, errors.New("AuthPair: can't sign, no private key")
	}
	return ed25519.Sign(pair.private, msg), nil
}

func (pair AuthPair) Verify(msg, testSig []byte) bool {
	return ed25519.Verify(pair.public, msg, testSig)
}

func (pair AuthPair) SignFile(path string) ([]byte, error) {
	if pair.private == nil {
		return nil, errors.New("AuthPair: can't sign file, no private key")
	}

	blake, _ := blake2b.New512(nil)

	fileHash, err := HashFile(path, blake)
	if err != nil {
		return nil, err
	}

	sig, err := pair.Sign(fileHash)
	if err != nil {
		// this should be impossible, due to the earlier check but i'll check anyways
		// maybe the state of pair.private has changed from another thread?
		return nil, errors.Wrap(err, "AuthPair: error signing file")
	}
	return sig, nil
}

func (pair AuthPair) VerifyFile(path string, testSig []byte) (bool, error) {
	blake, _ := blake2b.New512(nil)
	fileHash, err := HashFile(path, blake)
	if err != nil {
		return false, err
	}

	return pair.Verify(fileHash, testSig), nil
}
