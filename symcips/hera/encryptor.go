package hera

import (
	"HHESoK"
	"encoding/binary"
	"fmt"
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
	p := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	size := len(plaintext)
	numBlock := int(math.Ceil(float64(size / blockSize)))
	if HHESoK.DEBUG {
		fmt.Printf("=== Number of Block: %d\n", numBlock)
	}
	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	// Ciphertext
	ciphertext := make(HHESoK.Ciphertext, size)
	copy(ciphertext, plaintext)
	// Keystream
	for i := 0; i < numBlock; i++ {
		z := make(HHESoK.Block, blockSize)
		copy(z, enc.her.keyStream(nonces[i]))
		// encrypt the plaintext
		ciphertext[i] = (ciphertext[i] + z[i]) % p
	}
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	logger.PrintDataLen(ciphertext)
	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext HHESoK.Ciphertext) HHESoK.Plaintext {
	p := enc.her.params.GetModulus()
	blockSize := enc.her.params.GetBlockSize()
	size := len(ciphertext)
	numBlock := int(math.Ceil(float64(size / blockSize)))
	if HHESoK.DEBUG {
		fmt.Printf("=== Number of Block: %d\n", numBlock)
	}
	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	// Ciphertext
	plaintext := make(HHESoK.Plaintext, size)
	copy(plaintext, ciphertext)
	// Keystream
	for i := 0; i < numBlock; i++ {
		z := make(HHESoK.Block, blockSize)
		copy(z, enc.her.keyStream(nonces[i]))
		// decrypt the plaintext
		plaintext[i] = (plaintext[i] + z[i]) % p
	}
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	logger.PrintDataLen(plaintext)
	return plaintext
}

// KeyStream takes len(plaintext) as input and generate a keyStream
func (enc encryptor) KeyStream(size int) (keyStream HHESoK.Matrix) {
	blockSize := enc.her.params.GetBlockSize()
	numBlock := int(math.Ceil(float64(size / blockSize)))
	if HHESoK.DEBUG {
		fmt.Printf("=== Number of Block: %d\n", numBlock)
	}
	// Nonce and Counter
	nonces := make([][]byte, numBlock)
	// set nonce up to blockSize
	n := 123456789
	for i := 0; i < numBlock; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	// Key stream generation
	keyStream = make(HHESoK.Matrix, numBlock)
	for i := 0; i < numBlock; i++ {
		copy(keyStream[i], enc.her.keyStream(nonces[i]))
	}
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	logger.PrintDataLen(keyStream[0])
	return
}
