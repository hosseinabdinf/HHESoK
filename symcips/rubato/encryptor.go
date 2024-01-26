package rubato

import (
	"HHESoK/symcips"
	"encoding/binary"
)

type Encryptor interface {
	Encrypt(plaintext symcips.Plaintext) symcips.Ciphertext
	Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext
}

type encryptor struct {
	rub rubato
}

func (enc encryptor) Encrypt(plaintext symcips.Plaintext) symcips.Ciphertext {
	N := enc.rub.params.GetBlockSize()
	p := enc.rub.params.GetModulus()
	outputSize := enc.rub.params.GetBlockSize() - 4
	ciphertext := make(symcips.Ciphertext, len(plaintext))

	nonces := make([][]byte, N)
	// set nonce up to N
	n := 123456789
	for i := 0; i < N; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	counter := make([]byte, 8)

	ks := make(symcips.Matrix, N)
	for i := 0; i < N; i++ {
		z := make(symcips.Block, outputSize)
		binary.BigEndian.PutUint64(counter, uint64(i+1))
		copy(z, enc.rub.keyStream(nonces[i], counter))
		ks[i] = z
		//fmt.Println("ctr: ", counter)
		//fmt.Println("nonce: ", nonces[i])
		//fmt.Println("KeySt: ", z)
	}
	// encrypt the plaintext
	copy(ciphertext, plaintext)
	for i := 0; i < outputSize; i++ {
		ciphertext[i] = (ciphertext[i] + ks[0][i]) % p
	}
	// log for debug
	//fmt.Println(ks[0])
	//symcips.Uint64ToHex(plaintext)
	//symcips.Uint64ToHex(ciphertext)

	return ciphertext
}

func (enc encryptor) Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext {
	N := enc.rub.params.GetBlockSize()
	p := enc.rub.params.GetModulus()
	outputSize := enc.rub.params.GetBlockSize() - 4
	plaintext := make(symcips.Plaintext, len(ciphertext))

	nonces := make([][]byte, N)
	// set nonce up to N
	n := 123456789
	for i := 0; i < N; i++ {
		nonces[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(nonces[i], uint64(i+n))
	}
	counter := make([]byte, 8)

	// KS[N][OutputSize]
	ks := make(symcips.Matrix, N)
	for i := 0; i < N; i++ {
		z := make(symcips.Block, outputSize)
		binary.BigEndian.PutUint64(counter, uint64(i+1))
		copy(z, enc.rub.keyStream(nonces[i], counter))
		ks[i] = z
	}
	// decrypt the ciphertext
	copy(plaintext, ciphertext)
	for i := 0; i < outputSize; i++ {
		plaintext[i] = (plaintext[i] + ks[0][i]) % p
	}
	return plaintext
}
