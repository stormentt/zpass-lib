package crypto

import (
	"testing"

	"github.com/stormentt/zpass-lib/random"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestNewAuthPair(t *testing.T) {
	pair, err := NewAuthPair()
	assert.NoError(t, err)

	assert.NotNil(t, pair.private)
	assert.NotNil(t, pair.public)
}

func TestAuthPairFromBytes(t *testing.T) {
	privBytes, err := random.Bytes(64)
	assert.NoError(t, err)

	pubBytes, err := random.Bytes(32)
	assert.NoError(t, err)

	invalidBytes, err := random.Bytes(128)
	assert.NoError(t, err)

	priv, err := AuthPairFromBytes(privBytes)
	assert.NoError(t, err)

	pub, err := AuthPairFromBytes(pubBytes)
	assert.NoError(t, err)

	_, err = AuthPairFromBytes(invalidBytes)
	assert.Error(t, err)

	assert.NotNil(t, priv.private)
	assert.NotNil(t, priv.public)
	assert.Equal(t, privBytes, priv.raw)

	assert.Nil(t, pub.private)
	assert.NotNil(t, pub.public)
	assert.Equal(t, pubBytes, pub.raw)

	clearBytes := func(b []byte) {
		for i := 0; i < len(b); i++ {
			b[i] = 0
		}
	}

	clearBytes(privBytes)
	clearBytes(pubBytes)

	assert.NotEqual(t, privBytes, []byte(priv.private))
	assert.NotEqual(t, privBytes[32:], []byte(priv.public))

	assert.NotEqual(t, pubBytes, []byte(pub.public))
}

func TestBytes(t *testing.T) {
	pair, err := NewAuthPair()
	assert.Nil(t, err)

	allBytes := pair.Bytes()
	assert.NotNil(t, allBytes)
	assert.Len(t, allBytes, ed25519.PrivateKeySize)

	pair.private = nil
	pubBytes := pair.Bytes()
	assert.NotNil(t, pubBytes)
	assert.Len(t, pubBytes, ed25519.PublicKeySize)
}

func TestAuthSignatures(t *testing.T) {
	msg := []byte("Hello World!")
	bad := []byte("Goodnight World!")

	pair, err := NewAuthPair()
	assert.NoError(t, err)

	sig, err := pair.Sign(msg)
	assert.NoError(t, err)
	assert.Len(t, sig, ed25519.SignatureSize)

	badSig, err := pair.Sign(bad)
	assert.NoError(t, err)
	assert.Len(t, badSig, ed25519.SignatureSize)

	valid := pair.Verify(msg, sig)
	assert.True(t, valid)

	valid = pair.Verify(bad, sig)
	assert.False(t, valid)

	valid = pair.Verify(msg, badSig)
	assert.False(t, valid)

	pubPair, err := AuthPairFromBytes(pair.public)
	assert.NoError(t, err)

	_, err = pubPair.Sign(msg)
	assert.Error(t, err)

	valid = pubPair.Verify(msg, sig)
	assert.True(t, valid)

	valid = pubPair.Verify(bad, sig)
	assert.False(t, valid)

	valid = pubPair.Verify(msg, badSig)
	assert.False(t, valid)
}

func TestAuthFileSignatures(t *testing.T) {
	pair, err := NewAuthPair()
	assert.NoError(t, err)

	sig, err := pair.SignFile("signGoodTest")
	assert.NoError(t, err)
	assert.Len(t, sig, ed25519.SignatureSize)

	badSig, err := pair.SignFile("signBadTest")
	assert.NoError(t, err)
	assert.Len(t, badSig, ed25519.SignatureSize)

	assert.NotEqual(t, sig, badSig)

	valid, err := pair.VerifyFile("signGoodTest", sig)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = pair.VerifyFile("signBadTest", sig)
	assert.NoError(t, err)
	assert.False(t, valid)

	valid, err = pair.VerifyFile("signGoodTest", badSig)
	assert.NoError(t, err)
	assert.False(t, valid)

	pubPair, err := AuthPairFromBytes(pair.public)
	assert.NoError(t, err)

	_, err = pubPair.SignFile("signGoodTest")
	assert.Error(t, err)

	valid, err = pubPair.VerifyFile("signGoodTest", sig)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = pubPair.VerifyFile("signBadTest", sig)
	assert.NoError(t, err)
	assert.False(t, valid)

	valid, err = pubPair.VerifyFile("signGoodTest", badSig)
	assert.NoError(t, err)
	assert.False(t, valid)
}
