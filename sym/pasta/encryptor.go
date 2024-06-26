package pasta

import (
	"HHESoK"
	"encoding/binary"
	"math"
)

type Encryptor interface {
	Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext
	Decrypt(ciphertext HHESoK.Ciphertext) HHESoK.Plaintext
}

type encryptor struct {
	pas pasta
}

// Encrypt plaintext
func (enc encryptor) Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext {
	var size = uint64(len(plaintext))
	var plainSize = uint64(enc.pas.params.GetPlainSize())
	var numBlock = math.Ceil(float64(size / plainSize))
	var modulus = enc.pas.params.GetModulus()

	ciphertext := make(HHESoK.Ciphertext, size)
	copy(ciphertext, plaintext)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	counter := make([]byte, 8)

	for b := uint64(0); b < uint64(numBlock); b++ {
		binary.BigEndian.PutUint64(counter, b)
		keyStream := enc.pas.KeyStream(nonce, counter)
		for i := b * plainSize; i < (b+1)*plainSize && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + keyStream[i-b*plainSize]) % modulus
		}
	}

	return ciphertext
}

// Decrypt ciphertext
func (enc encryptor) Decrypt(ciphertext HHESoK.Ciphertext) HHESoK.Plaintext {
	var size = uint64(len(ciphertext))
	var plainSize = uint64(enc.pas.params.GetPlainSize())
	var cipherSize = uint64(enc.pas.params.GetCipherSize())
	var numBlock = uint64(math.Ceil(float64(size / cipherSize)))
	var modulus = enc.pas.params.GetModulus()

	plaintext := make(HHESoK.Plaintext, size)
	copy(plaintext, ciphertext)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))
	counter := make([]byte, 8)

	for b := uint64(0); b < numBlock; b++ {
		binary.BigEndian.PutUint64(counter, b)
		keyStream := enc.pas.KeyStream(nonce, counter)
		for i := b * cipherSize; i < (b+1)*cipherSize && i < size; i++ {
			if keyStream[i-b*plainSize] > plaintext[i] {
				plaintext[i] += modulus
			}
			plaintext[i] = plaintext[i] - keyStream[i-b*plainSize]
		}

	}

	return plaintext
}
