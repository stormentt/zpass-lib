package crypto

import (
	"testing"

	"github.com/stormentt/zpass-lib/random"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestNewIntegrityKey(t *testing.T) {
	key, err := NewIntegrityKey()
	assert.NoError(t, err)

	assert.Len(t, key, 64)
}

func TestIntegSignatures(t *testing.T) {
	key, err := NewIntegrityKey()
	assert.NoError(t, err)

	msg := []byte("Hello World!")
	bad := []byte("Goodbye World!")

	sig, err := key.Sign(msg)
	assert.NoError(t, err)
	assert.Len(t, sig, blake2b.Size)

	badSig, err := key.Sign(bad)
	assert.NoError(t, err)
	assert.Len(t, badSig, blake2b.Size)

	assert.NotEqual(t, sig, badSig)

	valid, err := key.Verify(msg, sig)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = key.Verify(bad, sig)
	assert.NoError(t, err)
	assert.False(t, valid)

	valid, err = key.Verify(msg, badSig)
	assert.NoError(t, err)
	assert.False(t, valid)

	// Test Bad Keys (should error every time)
	badKeyBytes, err := random.Bytes(128)
	assert.NoError(t, err)
	badKey := IntegrityKey(badKeyBytes)

	_, err = badKey.Sign(msg)
	assert.Error(t, err)

	_, err = badKey.Verify(bad, badSig)
	assert.Error(t, err)
}

func TestIntegFileSignatures(t *testing.T) {
	key, err := NewIntegrityKey()
	assert.NoError(t, err)

	sig, err := key.SignFile("signGoodTest")
	assert.NoError(t, err)
	assert.Len(t, sig, blake2b.Size)

	badSig, err := key.SignFile("signBadTest")
	assert.NoError(t, err)
	assert.Len(t, badSig, blake2b.Size)

	assert.NotEqual(t, sig, badSig)

	valid, err := key.VerifyFile("signGoodTest", sig)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = key.VerifyFile("signBadTest", sig)
	assert.NoError(t, err)
	assert.False(t, valid)

	valid, err = key.VerifyFile("signGoodTest", badSig)
	assert.NoError(t, err)
	assert.False(t, valid)

	// Test Bad Keys (should error every time)
	badKeyBytes, err := random.Bytes(128)
	assert.NoError(t, err)
	badKey := IntegrityKey(badKeyBytes)

	_, err = badKey.SignFile("signGoodTest")
	assert.Error(t, err)

	_, err = badKey.VerifyFile("signGoodTest", sig)
	assert.Error(t, err)
}
