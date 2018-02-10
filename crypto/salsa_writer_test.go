package crypto

import (
	"io"
	"math/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func randomCopy(out io.Writer, in io.Reader) (int64, error) {
	data := make([]byte, FileChunkSize)
	total := int64(0)
	for {
		data := data[:rand.Intn(FileChunkSize)]
		n, err := in.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			return total, err
		}
		data = data[:n]
		written, err := out.Write(data)
		if err != nil {
			return total + int64(written), err
		}
		total += int64(written)
	}
	return total, nil
}

func TestSalsaWriter(t *testing.T) {
	encKey, err := NewEncryptionKey()
	assert.NoError(t, err)

	intKey, err := NewIntegrityKey()
	assert.NoError(t, err)

	// Open & Create Test files
	in, err := os.Open("testSalsaWriter")
	assert.NoError(t, err)

	encDirect, err := os.Create("testSalsaWriter-Direct.enc")
	assert.NoError(t, err)

	encRandom, err := os.Create("testSalsaWriter-Random.enc")
	assert.NoError(t, err)

	// Direct Copying Test
	swDirect, err := NewSalsaWriter(encKey, intKey, encDirect)
	assert.NoError(t, err)

	_, err = io.Copy(swDirect, in)
	assert.NoError(t, err)

	err = swDirect.Close()
	assert.NoError(t, err)

	// Random Copying Test
	in.Seek(0, 0)

	swRandom, err := NewSalsaWriter(encKey, intKey, encRandom)
	assert.NoError(t, err)

	_, err = randomCopy(swRandom, in)
	assert.NoError(t, err)

	err = swRandom.Close()
	assert.NoError(t, err)

	// Sync
	err = encDirect.Sync()
	assert.NoError(t, err)

	err = encRandom.Sync()
	assert.NoError(t, err)

	// Seek back to starts
	_, err = in.Seek(0, 0)
	assert.NoError(t, err)

	_, err = encDirect.Seek(0, 0)
	assert.NoError(t, err)

	_, err = encRandom.Seek(0, 0)
	assert.NoError(t, err)

	// Create Decrypted Versions
	decDirect, err := os.Create("testSalsaWriter-Direct.dec")
	assert.NoError(t, err)

	decRandom, err := os.Create("testSalsaWriter-Random.dec")
	assert.NoError(t, err)

	// Direct Copying Test
	srDirect, err := NewSalsaReader(encKey, intKey, encDirect)
	assert.NoError(t, err)

	_, err = io.Copy(decDirect, srDirect)
	assert.NoError(t, err)

	// Random Copying Test
	srRandom, err := NewSalsaReader(encKey, intKey, encRandom)
	assert.NoError(t, err)

	_, err = randomCopy(decRandom, srRandom)
	assert.NoError(t, err)

	// Sync
	err = decDirect.Sync()
	assert.NoError(t, err)

	err = decRandom.Sync()
	assert.NoError(t, err)

	// Seek back to starts
	_, err = decDirect.Seek(0, 0)
	assert.NoError(t, err)

	_, err = decRandom.Seek(0, 0)
	assert.NoError(t, err)

	// Hash Files
	blake, _ := blake2b.New512(nil)

	inHash, err := HashReader(in, blake)
	assert.NoError(t, err)

	blake.Reset()

	decDirectHash, err := HashReader(decDirect, blake)
	assert.NoError(t, err)

	blake.Reset()

	decRandomHash, err := HashReader(decRandom, blake)
	assert.NoError(t, err)

	// Test Hashes
	assert.Equal(t, inHash, decDirectHash)
	assert.Equal(t, inHash, decRandomHash)

}
