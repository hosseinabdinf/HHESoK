package hera

import "HHESoK/symcips"

type Encryptor interface {
	Encrypt(plaintext symcips.Plaintext) symcips.Ciphertext
	Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext
}

type encryptor struct {
	her hera
}

// Encrypt plaintext
func (enc encryptor) Encrypt(plaintext symcips.Plaintext) symcips.Ciphertext {

	ciphertext := make(symcips.Ciphertext, 100)

	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext {
	plaintext := make(symcips.Plaintext, 100)

	return plaintext
}
