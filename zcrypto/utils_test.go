package zcrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashFile(t *testing.T) {
	hasher := sha256.New()

	knownHash, err := hex.DecodeString("70f0cca735ac11b7bf6627d24d411184f8de15c8551c94f93656c3fd1bf10c4a")
	assert.NoError(t, err)

	fileHash, err := HashFile("hashFileTest", hasher)
	assert.NoError(t, err)

	assert.Equal(t, fileHash, knownHash)
}
