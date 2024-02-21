package pasta

import (
	"HHESoK"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

type Encryptor interface {
	EncryptSymKey(batchEncoder bool) *rlwe.Ciphertext
	Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext
	TranCipher(ciphertext HHESoK.Ciphertext, batchEncoder bool) (res []*rlwe.Ciphertext)
	Decrypt(ciphertexts *rlwe.Ciphertext) (res HHESoK.Plaintext)
}

type encryptor struct {
	//hepa hePasta
}

// Encrypt plaintext
func (enc encryptor) Encrypt(plaintext HHESoK.Plaintext) HHESoK.Ciphertext {
	panic("There is no need to run this function!")
	//var nonce = uint64(123456789)
	var size = uint64(len(plaintext))
	//var plainSize = uint64(enc.pas.params.GetPlainSize())
	//var numBlock = math.Ceil(float64(size / plainSize))
	//var modulus = enc.pas.params.GetModulus()

	ciphertext := make(HHESoK.Ciphertext, size)
	copy(ciphertext, plaintext)

	//for b := uint64(0); b < uint64(numBlock); b++ {
	//	keyStream := enc.pas.keyStream(nonce, b)
	//	for i := b * plainSize; i < (b+1)*plainSize && i < size; i++ {
	//		ciphertext[i] = (ciphertext[i] + keyStream[i-b*plainSize]) % modulus
	//	}
	//}

	return ciphertext
}

func (enc encryptor) EncryptSymKey(batchEncoder bool) (key *rlwe.Ciphertext) {
	//fvParams := enc.hepa.bfvParams
	//sKey := enc.hepa.params.secretKey
	//T := enc.hepa.params.plainMod
	//halfSlots := enc.hepa.halfSlots
	//
	//tempKey := make(HHESoK.Key, halfSlots+T)
	//for i := uint64(0); i < T; i++ {
	//	tempKey[i] = sKey[i]
	//	tempKey[i+halfSlots] = sKey[i+T]
	//}
	//pKey := bfv.NewPlaintext(fvParams, fvParams.MaxLevel())
	//err := enc.hepa.encoder.Encode(tempKey, pKey)
	//if err != nil {
	//	panic(err)
	//}
	//err = enc.hepa.encryptor.Encrypt(pKey, key)
	//if err != nil {
	//	panic(err)
	//}

	return
}

// TranCipher convert the symmetrically encrypted ciphertext into homomorphically encrypted cipher
//func (enc encryptor) TranCipher(key *rlwe.Ciphertext, ciphertext HHESoK.Ciphertext, batchEncoder bool) (res []*rlwe.Ciphertext) {
//
//
//}

// Decrypt homomorphic ciphertext
func (enc encryptor) Decrypt(ciphertexts *rlwe.Ciphertext) (res HHESoK.Plaintext) {
	//params := enc.hepa.params
	//dec := enc.hepa.decryptor
	//en := enc.hepa.encoder
	//
	//res = make(HHESoK.Plaintext, params.GetPlainSize())
	//plaintext := dec.DecryptNew(ciphertexts)
	//err := en.Decode(plaintext, res)
	//if err != nil {
	//	panic(err)
	//}
	//
	return
}
