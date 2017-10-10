package crypt_test

import (
	"bytes"
	"golang.org/x/crypto/chacha20poly1305"
	"testing"
	"zpass-lib/crypt"
)

func TestKeyGen(t *testing.T) {
	var c crypt.ChaCha20Crypter
	key, err := c.GenKey()

	if len(key) != chacha20poly1305.KeySize {
		t.Errorf("GenKey() Error: %v", err)
		t.Fatalf("GenKey() key incorrect size, %v is not %v", len(key), chacha20poly1305.KeySize)
	}
}

func TestKDF(t *testing.T) {
	var c crypt.ChaCha20Crypter
	key, salt, err := c.DeriveKey("Hello World!")
	if err != nil {
		t.Fatalf("DeriveKey() failed. Error: %v", err)
	}

	if len(key) != chacha20poly1305.KeySize {
		t.Fatalf("DeriveKey() key incorrect size, %v is not %v", len(key), chacha20poly1305.KeySize)
	}

	rederived, err := c.CalcKey("Hello World!", salt)
	if err != nil {
		t.Errorf("CalcKey() failed. Error: %v", err)
	}

	if !bytes.Equal(key, rederived) {
		t.Errorf("DeriveKey() did not match CalcKey()")
	}

	wrongPass, _ := c.CalcKey("Wrong Password!", salt)
	wrongSalt, _ := c.CalcKey("Hello World!", []byte{'n', 'o'})

	if bytes.Equal(key, wrongPass) {
		t.Errorf("Using the wrong password resulted in the same key")
	}

	if bytes.Equal(key, wrongSalt) {
		t.Errorf("Using the wrong salt resulted in the same key")
	}
}

func BenchmarkKDF(b *testing.B) {
	var c crypt.ChaCha20Crypter
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.DeriveKey("hello world")
	}
}

func TestEncryption(t *testing.T) {
	plaintext := []byte("Hello World! This is a test!")
	var c crypt.ChaCha20Crypter
	c.Key, _ = c.GenKey()

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
	c.Key, _ = c.GenKey()
	wrongKey.Key, _ = wrongKey.GenKey()

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
	c.Key, _ = c.GenKey()

	encrypted, _ := c.Encrypt(plaintext)
	encrypted[len(encrypted)-1] = encrypted[len(encrypted)-1] ^ 255

	decrypted, err := c.Decrypt(encrypted)
	if err == nil {
		t.Logf("Decrypted: ", string(decrypted))
		t.Error("Decrypt() did not return an error after tampering")
	}
}
