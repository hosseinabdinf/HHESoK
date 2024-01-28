package rubato

import (
	"HHESoK"
	"encoding/binary"
	"fmt"
	"math"
)

type Encryptor interface {
	Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext
	Decrypt(ciphertext HHESoK.Ciphertext) HHESoK.Plaintext
}

type encryptor struct {
	rub rubato
}

func (enc encryptor) Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext {
	p := enc.rub.params.GetModulus()
	blockSize := enc.rub.params.GetBlockSize()
	outputSize := enc.rub.params.GetBlockSize() - 4
	size := len(plaintext)
	numBlock := int(math.Ceil(float64(size / outputSize)))
	if HHESoK.DEBUG {
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
	counter := make([]byte, 8)
	// Ciphertext
	ciphertext := make(HHESoK.Ciphertext, size)
	copy(ciphertext, plaintext)
	// Keystream
	for i := 0; i < numBlock; i++ {
		z := make(HHESoK.Block, outputSize)
		binary.BigEndian.PutUint64(counter, uint64(i+1))
		// counter mode
		copy(z, enc.rub.keyStream(nonces[i], counter))
		// encrypt the plaintext
		ciphertext[i] = (ciphertext[i] + z[i]) % p
	}
	return ciphertext
}

func (enc encryptor) Decrypt(ciphertext HHESoK.Ciphertext) HHESoK.Plaintext {
	p := enc.rub.params.GetModulus()
	blockSize := enc.rub.params.GetBlockSize()
	outputSize := enc.rub.params.GetBlockSize() - 4
	size := len(ciphertext)
	numBlock := int(math.Ceil(float64(size / outputSize)))
	if HHESoK.DEBUG {
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
	counter := make([]byte, 8)
	// Ciphertext
	plaintext := make(HHESoK.Plaintext, size)
	copy(plaintext, ciphertext)
	// Keystream
	for i := 0; i < numBlock; i++ {
		z := make(HHESoK.Block, outputSize)
		binary.BigEndian.PutUint64(counter, uint64(i+1))
		// counter mode
		copy(z, enc.rub.keyStream(nonces[i], counter))
		// encrypt the plaintext
		plaintext[i] = (plaintext[i] + z[i]) % p
	}
	return plaintext
}
