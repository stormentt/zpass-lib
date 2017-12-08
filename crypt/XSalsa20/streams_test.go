package XSalsa20_test

import (
	"io"
	"os"
	"testing"

	"github.com/stormentt/zpass-lib/crypt/XSalsa20"
	"github.com/stormentt/zpass-lib/random"
)

func TestStreams(t *testing.T) {
	key, _ := random.Bytes(64)

	cipherText, _ := os.Create("cipher")
	cw := XSalsa20.NewCryptWriter(cipherText, key)

	plain, _ := os.Open("testBig")
	io.Copy(cw, plain)

	plain.Close()
	cw.Close()

	newCT, _ := os.Open("cipher")
	cr := XSalsa20.NewCryptReader(newCT, key)

	err := cr.Initialize()
	if err != nil {
		t.Errorf("Failed: %v", err)
	}

	decrypted, _ := os.Create("decrypted")
	io.Copy(decrypted, cr)
}
