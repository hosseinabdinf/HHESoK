package rubato

import (
	"HHESoK/symcips"
	"crypto/rand"
	"fmt"
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

	nonces := make([][]byte, N)
	for i := 0; i < N; i++ {
		nonces[i] = make([]byte, 8)
		_, err := rand.Read(nonces[i])
		if err != nil {
			return nil
		}
	}
	counter := make([]byte, 8)
	_, err := rand.Read(counter)
	if err != nil {
		return nil
	}

	ks := make(symcips.Matrix, N)
	for i := 0; i < N; i++ {
		ks[i] = enc.rub.keyStream(nonces[i], counter)
		//symcips.Uint64ToHex(ks[i])
	}
	fmt.Println(ks)

	ciphertext := make(symcips.Ciphertext, 100)
	return ciphertext
}

func (enc encryptor) Decrypt(ciphertext symcips.Ciphertext) symcips.Plaintext {

	plaintext := make(symcips.Plaintext, 100)
	return plaintext
}
