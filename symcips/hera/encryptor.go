package hera

import (
	"HHESoK/symcips"
	"encoding/binary"
	"fmt"
	"math"
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
	p := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	size := len(plaintext)
	numBlock := int(math.Ceil(float64(size / blockSize)))
	if symcips.DEBUG {
		fmt.Printf("=== Number of Block: %d\n", numBlock)
	}
	// Nonce and Counter
	nonces := make([][]byte, blockSize)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < blockSize; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	// Ciphertext
	ciphertext := make(symcips.Ciphertext, size)
	copy(ciphertext, plaintext)
	// Keystream
	for i := 0; i < numBlock; i++ {
		z := make(symcips.Block, blockSize)
		copy(z, enc.her.keyStream(nonces[i]))
		// encrypt the plaintext
		ciphertext[i] = (ciphertext[i] + z[i]) % p
	}
	logger := symcips.NewLogger(symcips.DEBUG)
	logger.PrintDataLen(ciphertext)
	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext {
	p := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	size := len(ciphertext)
	numBlock := int(math.Ceil(float64(size / blockSize)))
	if symcips.DEBUG {
		fmt.Printf("=== Number of Block: %d\n", numBlock)
	}
	// Nonce and Counter
	nonces := make([][]byte, blockSize)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < blockSize; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	// Ciphertext
	plaintext := make(symcips.Plaintext, size)
	copy(plaintext, ciphertext)
	// Keystream
	for i := 0; i < numBlock; i++ {
		z := make(symcips.Block, blockSize)
		copy(z, enc.her.keyStream(nonces[i]))
		// decrypt the plaintext
		plaintext[i] = (plaintext[i] + z[i]) % p
	}
	logger := symcips.NewLogger(symcips.DEBUG)
	logger.PrintDataLen(plaintext)
	return plaintext
}
