package crypto

import (
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/stormentt/zpass-lib/util/slices"
)

// CryptoProvider provides encryption, integrity, and authentication using symmetric keys for encryption and public/private keys for authentication.
type CryptoProvider struct {
	encryptionKey EncryptionKey
	integrityKey  IntegrityKey
	authPair      AuthPair
	raw           []byte
}

// NewCryptoProvider generates a new CryptoProvider with random keys
func NewCryptoProvider() (*CryptoProvider, error) {
	var err error

	encKey, err := NewEncryptionKey()
	if err != nil {
		return nil, err
	}

	intKey, err := NewIntegrityKey()
	if err != nil {
		return nil, err
	}

	authPair, err := NewAuthPair()

	provider := CryptoProvider{
		encryptionKey: encKey,
		integrityKey:  intKey,
		authPair:      authPair,
		raw:           slices.Combine(encKey, intKey, authPair.Bytes()),
	}

	return &provider, nil
}

// CryptoProviderFromBytes creates a CryptoProvider from a byte slice
//
// b must be EncKeySize+IntKeySize+AuthFullSize in length
func CryptoProviderFromBytes(b []byte) (*CryptoProvider, error) {
	provider := new(CryptoProvider)
	provider.raw = make([]byte, len(b))
	copy(provider.raw, b)

	if len(b) == EncKeySize+IntKeySize+AuthFullSize {
		provider.encryptionKey = provider.raw[:EncKeySize]
		provider.integrityKey = provider.raw[EncKeySize:IntKeySize]
		authPair, _ := AuthPairFromBytes(provider.raw[EncKeySize+IntKeySize:])
		provider.authPair = authPair
	} else {
		return nil, CryptoProviderBadSizeError{len(b)}
	}

	return provider, nil
}

// Encrypt encrypts a byte slice & generates a MAC
//
// The MAC is prepended to the encrypted slice. This is to encourage MAC validation before decryption.
func (c *CryptoProvider) Encrypt(msg []byte) ([]byte, error) {
	ciphertext, err := c.encryptionKey.Encrypt(msg)
	if err != nil {
		return nil, err
	}

	mac, err := c.integrityKey.Sign(ciphertext)
	if err != nil {
		return nil, err
	}

	return slices.Combine(mac, ciphertext), nil
}

// Decrypt decrypts an encrypted byte slice
//
// If the message's MAC is invalid decryption will return a nil & an error
func (c *CryptoProvider) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < MsgOverhead {
		return nil, MsgTooShortError{wanted: MsgOverhead, size: len(msg)}
	}

	sig := msg[:IntHashSize]
	ciphertext := msg[IntHashSize:]

	valid, err := c.integrityKey.Verify(ciphertext, sig)
	if err != nil {
		return nil, err
	} else if valid == false {
		return nil, InvalidSignatureError{sig}
	}

	plaintext, err := c.encryptionKey.Decrypt(msg)
	return plaintext, err
}

// EncryptFile encrypts a file & generates a MAC
//
// The MAC is prepended to the encrypted file. This is to encourage MAC validation before decryption.
func (c *CryptoProvider) EncryptFile(inPath, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return errors.WithStack(err)
	}

	out, err := os.Open(outPath)
	if err != nil {
		return errors.WithStack(err)
	}

	sw, err := NewSalsaWriter(c.encryptionKey, c.integrityKey, out)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = io.Copy(sw, in)
	if err != nil {
		return errors.WithStack(err)
	}

	err = sw.Close()
	if err != nil {
		return errors.WithStack(err)
	}

	_ = in.Close()
	err = out.Close()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// DecryptFile decrypts a file
//
// If the file's MAC is invalid decryption will return an error
func (c *CryptoProvider) DecryptFile(inPath, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return errors.WithStack(err)
	}

	out, err := os.Open(outPath)
	if err != nil {
		return errors.WithStack(err)
	}

	sr, err := NewSalsaReader(c.encryptionKey, c.integrityKey, in)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = io.Copy(out, sr)
	if err != nil {
		return errors.WithStack(err)
	}

	_ = in.Close()
	err = out.Close()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
