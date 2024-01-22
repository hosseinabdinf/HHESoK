package hera

import (
	"HHESoK/symcips"
	"crypto/rand"
)

type Encryptor interface {
	Encrypt(plaintext symcips.Plaintext) symcips.Ciphertext
	Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext
}

type encryptor struct {
	her hera
}

// Encrypt plaintext
func (enc encryptor) Encrypt(plaintext symcips.Plaintext) symcips.Ciphertext {
	// generate nonce
	fvSlots := 15
	nonces := make([][]byte, fvSlots)
	for i := 0; i < fvSlots; i++ {
		nonces[i] = make([]byte, 64)
		_, err := rand.Read(nonces[i])
		if err != nil {
			panic(err)
		}
	}

	keystream := make([][]uint64, fvSlots)
	for i := 0; i < fvSlots; i++ {
		//keystream[i] = plainHera(numRound, nonces[i], key, params.PlainModulus())
		keystream[i] = enc.her.keyStream(nonces[i])
	}
	ciphertext := make(symcips.Ciphertext, 100)

	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext {
	plaintext := make(symcips.Plaintext, 100)

	return plaintext
}
