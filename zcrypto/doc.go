/*
Package zcrypto provides easy to use cryptographic interfaces.

When using zcrypto for encrypting messages and files, you are encouraged to use the CryptoProvider interface rather than the EncryptionKey type. EncryptionKey does not perform any sort of integrity checking, CryptoProvider combines an EncryptionKey and an IntegrityKey to provide both confidentiality and integrity.

Example Usage:
	func main() {
		cr, err := zcrypto.NewCryptoProvider()

		// Encrypting
		encrypted, err := cr.Encrypt([]byte("Hello World!"))
		err := cr.EncryptFile("sourceFile.txt", "encrypted.zpc")

		// Decrypting
		decrypted, err := cr.Decrypt(encrypted)
		err := cr.EncryptFile("encrypted.zpc", "decrypted.txt")

		// Signing
		sig, err := cr.Sign([]byte("Some important message"))
		fileSig, err := cr.SignFile("sourceFile.txt")

		// Verifying Signatures
		valid := cr.Verify([]byte("Some important message"), sig)
		validFile := cr.VerifyFile(sourceFile.txt, fileSig)
	}

Algorithms

XSalsa20 is used to encrypt data.

Blake2 with a secret key is used to provide message integrity.

Ed25519 is used for asymmetric signatures.


Encrypted Message Structure

Encrypted messages are formatted like so
	[MAC][Nonce][Ciphertext]

The MAC is calculated over the Nonce & Ciphertext. The MAC is first to encourage to verifying the MAC before decryption.

File Encryption

Files are encrypted & decrypted using the SalsaWriter and SalsaReader types. SalsaWriter & SalsaReader automatically handle chunking, maintaining the XSalsa20 counter, and calculating/verifying the file MAC.

SalsaWriter

Initializing a new SalsaWriter automatically writes out an IntHashSize block of zeros to the start of the io.WriteSeeker as a placeholder for the MAC. The MAC will be written out once SalsaWriter.Close() is called. SalsaWriter.Closed will be set to true and any further writes will fail with SalsaWriterClosedError.

SalsaReader

Initializing a new SalsaReader automatically checks the io.ReadSeeker's MAC. If the MAC is invalid, it will return a MACMismatchError and set SalsaReader.Integrous to false. Any further reads or seeks will fail with UnintegrousReadError.
*/
package zcrypto
