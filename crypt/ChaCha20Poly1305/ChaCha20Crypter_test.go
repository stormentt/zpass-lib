package ChaCha20Poly1305_test

import (
	"bytes"
	"testing"

	crypt "github.com/stormentt/zpass-lib/crypt/ChaCha20Poly1305"
)

func BenchmarkKDF(b *testing.B) {
	var c crypt.ChaCha20Crypter
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.DeriveKey([]byte("hello world"))
	}
}

func TestEncryption(t *testing.T) {
	plaintext := []byte("Hello World! This is a test!")
	var c crypt.ChaCha20Crypter
	err := c.GenKey()
	if err != nil {
		t.Errorf("Encrypt() failed: %v", err)
	}

	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		t.Errorf("Encrypt() failed: %v", err)
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Decrypt() failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypt() did not match plaintext.")
	}

}

func TestEncryptionWrongKey(t *testing.T) {
	plaintext := []byte("Hello World! This is a test!")
	var c crypt.ChaCha20Crypter
	var wrongKey crypt.ChaCha20Crypter
	c.GenKey()
	wrongKey.GenKey()

	encrypted, _ := c.Encrypt(plaintext)

	wrongDecrypted, err := wrongKey.Decrypt(encrypted)
	if err == nil {
		t.Error("WrongKey Decrypt did not return an error")
	}

	if bytes.Equal(plaintext, wrongDecrypted) {
		t.Error("WrongKey Decrypt equalled plaintext")
	}
}

func TestEncryptionTampered(t *testing.T) {
	plaintext := []byte("Hello World! This is a test!")
	var c crypt.ChaCha20Crypter
	c.GenKey()

	encrypted, _ := c.Encrypt(plaintext)
	encrypted[len(encrypted)-1] = encrypted[len(encrypted)-1] ^ 255

	decrypted, err := c.Decrypt(encrypted)
	if err == nil {
		t.Logf("Decrypted: %v", string(decrypted))
		t.Error("Decrypt() did not return an error after tampering")
	}
}
