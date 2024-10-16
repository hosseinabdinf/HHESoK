package hera

import (
	"HHESoK"
	"encoding/binary"
	"math"
)

type Encryptor interface {
	Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext
	Decrypt(ciphertext HHESoK.Ciphertext) HHESoK.Plaintext
	KeyStream(size int) HHESoK.Matrix
}

type encryptor struct {
	her hera
}

// Encrypt plaintext
func (enc encryptor) Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	var size = len(plaintext)
	var modulus = enc.her.params.GetModulus()
	var blockSize = enc.her.params.GetBlockSize()
	var numBlock = int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	ciphertext := make(HHESoK.Ciphertext, size)
	copy(ciphertext, plaintext)

	for i := 0; i < numBlock; i++ {
		z := make(HHESoK.Block, blockSize)
		copy(z, enc.her.KeyStream(nonces[i]))
		ciphertext[i] = (ciphertext[i] + z[i]) % modulus
	}

	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext HHESoK.Ciphertext) HHESoK.Plaintext {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)

	var size = len(ciphertext)
	var modulus = enc.her.params.GetModulus()
	var blockSize = enc.her.params.GetBlockSize()
	var numBlock = int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	plaintext := make(HHESoK.Plaintext, size)
	copy(plaintext, ciphertext)

	for i := 0; i < numBlock; i++ {
		z := make(HHESoK.Block, blockSize)
		copy(z, enc.her.KeyStream(nonces[i]))

		if z[i] > plaintext[i] {
			plaintext[i] += modulus
		}
		plaintext[i] = plaintext[i] - z[i]
	}

	return plaintext
}

// KeyStream takes len(plaintext) as input and generate a KeyStream
func (enc encryptor) KeyStream(size int) (keyStream HHESoK.Matrix) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)

	blockSize := enc.her.params.GetBlockSize()
	numBlock := int(math.Ceil(float64(size / blockSize)))
	logger.PrintFormatted("Number of Block: %d", numBlock)

	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}

	// generate key stream
	keyStream = make(HHESoK.Matrix, numBlock)
	for i := 0; i < numBlock; i++ {
		copy(keyStream[i], enc.her.KeyStream(nonces[i]))
	}

	return
}
