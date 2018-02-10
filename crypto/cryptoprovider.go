package crypto

import (
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/stormentt/zpass-lib/util/slices"
)

type CryptoProvider struct {
	encryptionKey EncryptionKey
	integrityKey  IntegrityKey
	authPair      AuthPair
	raw           []byte
}

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

func CryptoProviderFromBytes(b []byte) (*CryptoProvider, error) {
	provider := new(CryptoProvider)
	provider.raw = make([]byte, len(b))
	copy(provider.raw, b[:])

	if len(b) == EncKeySize+IntKeySize {
		provider.encryptionKey = provider.raw[:EncKeySize]
		provider.integrityKey = provider.raw[EncKeySize:]
	} else {
		return nil, errors.New("CryptoProvider: invalid []byte size")
	}

	return provider, nil
}

func (c *CryptoProvider) Encrypt(msg []byte) ([]byte, error) {
	ciphertext, err := c.encryptionKey.Encrypt(msg)
	if err != nil {
		return nil, err
	}

	sig, err := c.integrityKey.Sign(ciphertext)
	if err != nil {
		return nil, err
	}

	return slices.Combine(sig, ciphertext), nil
}

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
