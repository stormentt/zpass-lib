package zcrypto

const (
	// EncKeySize is the size of an encryption key.
	// We use XSalsa20 for encryption, so this is 32 bytes (256 bits).
	EncKeySize = 32
	// EncNonceSize is the size of our encryption nonce.
	// We use XSalsa20 for encryption, so this is 24 bytes (192 bits).
	EncNonceSize = 24
	// EncBlockSize is the size of our encryption blocks.
	// We use XSalsa20 for encryption, which operates on 64 byte (512 bit) blocks.
	EncBlockSize = 64

	// IntKeySize is the size of an integrity key.
	// We use Blake2-512 for integrity checking, so this is 64 bytes (512 bits).
	IntKeySize = 64
	// IntHashSize is the size of an integrity hash.
	// We use Blake2-512 for integrity checking, so this is 64 bytes (512 bits).
	IntHashSize = 64

	// AuthFullSize is the size of a keypair with both public & private keys.
	// We use ed25519 for signing, so this is (32 bytes + 32 bytes) = 64 bytes (512 bits).
	AuthFullSize = 64
	// AuthHalfSize is the size of a keypair with a single key.
	// zcrypto assumes if you only have one key that its a public key.
	// We use ed25519 for signing, so this is 32 bytes (256 bits).
	AuthHalfSize = 32
	// AuthSigSize is the size of a signature
	// We use ed25519 for signing, so this is 64 bytes (512 bits).
	AuthSigSize = 64

	// MsgOverhead is the overhead on a standard message (ie not a file)
	// Every message needs a new nonce and an integrity hash
	MsgOverhead = EncNonceSize + IntHashSize
	// FileOverhead is the overhead on an encrypted file
	// Every file needs a new nonce, integrity hash, and a counter representing the number of "dummy bytes" in that file
	FileOverhead = EncNonceSize + IntHashSize + 4 // 4 bytes for the int32 extraByte count

	// FileChunkSize is the size of chunk we use when reading in files.
	// We chunk files so smaller devices don't have to read the entire file into memory in order to decrypt.
	FileChunkSize = 128 * 1024
)
