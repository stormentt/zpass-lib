/*
Package crypto provides easy to use cryptographic interfaces

crypto uses XSalsa20 to encrypt messages, Keyed Blake2b to check integrity, and Ed25519 for public key authentication

EncryptionKeys are used to encrypt data

IntegrityKeys are used to check if encrypted data has been tampered with

AuthPairs are used to authenticate to servers
*/
package crypto
