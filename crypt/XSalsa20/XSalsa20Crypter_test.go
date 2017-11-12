package XSalsa20_test

import (
	"bytes"
	"testing"

	"github.com/stormentt/zpass-lib/crypt/XSalsa20"
)

func TestEncryptString(t *testing.T) {
	c, _ := XSalsa20.Create(nil)

	plain := []byte("test string")
	ciphertext, _ := c.Encrypt(plain)
	decrypted, _ := c.Decrypt(ciphertext)

	if !bytes.Equal(plain, decrypted) {
		t.Errorf("Decrypt failed")
	}
}

func TestTamper(t *testing.T) {
	c, _ := XSalsa20.Create(nil)

	plain := []byte("test string")
	ciphertext, _ := c.Encrypt(plain)
	ciphertext[4] = ciphertext[4] ^ 255
	_, err := c.Decrypt(ciphertext)
	if err == nil {
		t.Errorf("Tampered string did not trigger error")
	}
}

func TestEncryptFile(t *testing.T) {
	c, _ := XSalsa20.Create(nil)

	err := c.EncryptFile("plaintext.txt", "out")
	if err != nil {
		t.Errorf("EncryptFile() failed: %v", err)
	}

	err = c.DecryptFile("out", "decrypted.txt")
	if err != nil {
		t.Errorf("DecryptFile() failed: %v", err)
	}
}
