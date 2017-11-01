package XSalsa20_test

import (
	"testing"

	"github.com/stormentt/zpass-lib/crypt/XSalsa20"
)

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
