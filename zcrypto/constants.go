package zcrypto

const (
	EncKeySize   = 32
	EncNonceSize = 24
	EncBlockSize = 64

	IntKeySize  = 64
	IntHashSize = 64

	AuthFullSize = 64
	AuthHalfSize = 32
	AuthSigSize  = 64

	MsgOverhead  = EncNonceSize + IntHashSize
	FileOverhead = EncNonceSize + IntHashSize + 8

	FileChunkSize = 128 * 1024
)
