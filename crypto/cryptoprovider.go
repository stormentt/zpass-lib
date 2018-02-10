package crypto

import (
	"github.com/pkg/errors"
	"github.com/stormentt/zpass-lib/util/slices"
)

type CryptoProvider struct {
	encryptionKey EncryptionKey
	integrityKey  IntegrityKey
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

	provider := CryptoProvider{
		encryptionKey: encKey,
		integrityKey:  intKey,
		raw:           slices.Combine(encKey, intKey),
	}

	return &provider, nil
}

func CryptoProviderFromBytes(b []byte) (*CryptoProvider, error) {
	provider := new(CryptoProvider)
	provider.raw = make([]byte, len(b))
	copy(provider.raw, b[:])

	if len(b) == EncryptionKeyLength+IntegrityKeyLength {
		provider.encryptionKey = provider.raw[:EncryptionKeyLength]
		provider.integrityKey = provider.raw[EncryptionKeyLength:]
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
	if len(msg) <= 88 {
		return nil, errors.New("CryptoProvider: can't decrypt, msg too short")
	}

	sig := msg[:64]
	ciphertext := msg[64:]

	valid, err := c.integrityKey.Verify(ciphertext, sig)
	if err != nil {
		return nil, err
	} else if valid == false {
		return nil, errors.New("CryptoProvider: can't decrypt, invalid signature")
	}

	plaintext, err := c.encryptionKey.Decrypt(msg)
	return plaintext, err
}
