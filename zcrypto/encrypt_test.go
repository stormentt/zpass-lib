package zcrypto

import (
	"testing"

	"github.com/stormentt/zpass-lib/random"
	"github.com/stretchr/testify/assert"
)

func TestNewEncryptionKey(t *testing.T) {
	key, err := NewEncryptionKey()
	assert.NoError(t, err)
	assert.Len(t, key, EncKeySize)
}

func TestEncrypt(t *testing.T) {
	key, err := NewEncryptionKey()
	assert.NoError(t, err)

	wrongKey, err := NewEncryptionKey()
	assert.NoError(t, err)

	msg := []byte("Hello World!")
	ciphertext, err := key.Encrypt(msg)
	assert.NoError(t, err)
	assert.NotEqual(t, msg, ciphertext)
	assert.Len(t, ciphertext, 24+len(msg))

	plaintext, err := key.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, msg, plaintext)

	wrongPlain, err := wrongKey.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.NotEqual(t, wrongPlain, msg)

	badKeyBytes, err := random.Bytes(128)
	badKey := EncryptionKey(badKeyBytes)

	_, err = badKey.Encrypt(msg)
	assert.Error(t, err)

	_, err = badKey.Decrypt(ciphertext)
	assert.Error(t, err)
}
