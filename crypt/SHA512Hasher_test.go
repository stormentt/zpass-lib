package crypt_test

import (
	"crypto/sha512"
	"testing"
	"github.com/stormentt/zpass-lib/crypt"
)

func TestGenKey(t *testing.T) {
	var h crypt.Sha512Hasher
	key, err := h.GenKey()
	if len(key) != sha512.BlockSize {
		t.Errorf("GenKey() Error: %v", err)
		t.Fatalf("GenKey() key incorrect size, %v is not %v", len(key), sha512.BlockSize)
	}
}

func BenchmarkDigest(b *testing.B) {
	var h crypt.Sha512Hasher
	h.Key, _ = h.GenKey()
	plaintext := []byte("Hello World!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Digest(plaintext)
	}
}

func BenchmarkVerify(b *testing.B) {
	var h crypt.Sha512Hasher
	h.Key, _ = h.GenKey()
	plaintext := []byte("Hello World!")
	digested := h.Digest(plaintext)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Verify(plaintext, digested)
	}
}
func TestDigest(t *testing.T) {
	var h crypt.Sha512Hasher
	plaintext := []byte("Hello World!")
	h.Key, _ = h.GenKey()
	digested := h.Digest(plaintext)
	if len(digested) != sha512.Size {
		t.Fatalf("Digest() returned a value of incorrect size")
	}

	match := h.Verify(plaintext, digested)

	if match != true {
		t.Fatalf("Verify() returned false even though no tampering")
	}
}

func TestDigestTampering(t *testing.T) {
	var h crypt.Sha512Hasher
	plaintext := []byte("Hello World!")
	wrongtext := []byte("Hello Worlf!")
	h.Key, _ = h.GenKey()
	digested := h.Digest(plaintext)

	wrongtextValid := h.Verify(wrongtext, digested)
	if wrongtextValid == true {
		t.Fatalf("Verify() returned true even after tampering")
	}
}
