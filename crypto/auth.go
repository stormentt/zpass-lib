package crypto

import (
	"github.com/pkg/errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

// AuthPair provides authentication via public/private keys
type AuthPair struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	raw     []byte
}

// NewAuthPair generates a new public/private key pair
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

// AuthPairFromBytes creates an AuthPair from a byte slice
//
// b must be either AuthFullSize or AuthHalfSize in length
//
// If len(b) is AuthFullSize, the AuthPair will be able to sign & verify messages
//
// If len(b) is AuthHalfSize, the AuthPair will only be able to verify messages
func AuthPairFromBytes(b []byte) (AuthPair, error) {
	pair := AuthPair{}
	pair.raw = make([]byte, len(b))
	copy(pair.raw, b[:])

	if len(b) == AuthFullSize {
		pair.private = ed25519.PrivateKey(pair.raw)
		pair.public = ed25519.PublicKey(pair.raw[AuthHalfSize:])
	} else if len(b) == AuthHalfSize {
		pair.public = ed25519.PublicKey(pair.raw)
	} else {
		return AuthPair{}, AuthPairBadSizeError{len(b)}
	}

	return pair, nil
}

// Bytes returns a byte slice representing the AuthPair
func (pair AuthPair) Bytes() []byte {
	if pair.private != nil {
		return pair.private
	}

	return pair.public
}

// Sign generates a signature for a message.
// If the AuthPair does not have a private key this will return an error.
func (pair AuthPair) Sign(msg []byte) ([]byte, error) {
	if pair.private == nil {
		return nil, NoPrivKeyError{}
	}
	return ed25519.Sign(pair.private, msg), nil
}

// Verify checks a message against its signature
//
// If the signature is valid, it will return true. Otherwise, it will return false.
//
// If the AuthPair does not have a public key, it will return false
func (pair AuthPair) Verify(msg, testSig []byte) bool {
	if pair.public == nil {
		return false
	}

	return ed25519.Verify(pair.public, msg, testSig)
}

// SignFile generates a signature for a file.
// If the AuthPair does not have a private key this will return an error.
//
// SignFile first calculates the blake2b-512 hash of the file and then calls AuthPair.Sign on the resultant hash
func (pair AuthPair) SignFile(path string) ([]byte, error) {
	if pair.private == nil {
		return nil, NoPrivKeyError{}
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

// VerifyFile checks a file against its signature
//
// If the signature is valid, it will return true. Otherwise, it will return false.
//
// If the AuthPair does not have a public key, it will return false
func (pair AuthPair) VerifyFile(path string, testSig []byte) (bool, error) {
	blake, _ := blake2b.New512(nil)
	fileHash, err := HashFile(path, blake)
	if err != nil {
		return false, err
	}

	return pair.Verify(fileHash, testSig), nil
}
