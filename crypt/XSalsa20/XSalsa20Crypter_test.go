package XSalsa20_test

import (
	"testing"

	"github.com/stormentt/zpass-lib/crypt/XSalsa20"
)

func TestEncryptFile(t *testing.T) {
	c, _ := XSalsa20.Create(nil)

	c.EncryptFile("plaintext.txt", "out")
	c.DecryptFile("out", "decrypted.txt")
}
