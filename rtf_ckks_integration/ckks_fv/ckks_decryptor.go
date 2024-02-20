package ckks_fv

import (
	"HHESoK/rtf_ckks_integration/ring"
	"HHESoK/rtf_ckks_integration/utils"
)

// CKKSDecryptor is an interface for decrypting Ciphertexts. A Decryptor stores the secret-key.
type CKKSDecryptor interface {
	// DecryptNew decrypts the ciphertext and returns a newly created
	// plaintext. A Horner method is used for evaluating the decryption.
	// The level of the output plaintext is ciphertext.Level().
	DecryptNew(ciphertext *Ciphertext) (plaintext *Plaintext)

	// Decrypt decrypts the ciphertext and returns the result on the provided
	// receiver plaintext. A Horner method is used for evaluating the
	// decryption.
	// The level of the output plaintext is min(ciphertext.Level(), plaintext.Level())
	Decrypt(ciphertext *Ciphertext, plaintext *Plaintext)
}

// ckksDecryptor is a structure used to decrypt ciphertext. It stores the secret-key.
type ckksDecryptor struct {
	params *Parameters
	ringQ  *ring.Ring
	sk     *SecretKey
}

// NewCKKSDecryptor instantiates a new Decryptor that will be able to decrypt ciphertexts
// encrypted under the provided secret-key.
func NewCKKSDecryptor(params *Parameters, sk *SecretKey) CKKSDecryptor {

	if sk.Value.Degree() != params.N() {
		panic("secret_key is invalid for the provided parameters")
	}

	var q *ring.Ring
	var err error
	if q, err = ring.NewRing(params.N(), params.qi); err != nil {
		panic(err)
	}

	return &ckksDecryptor{
		params: params.Copy(),
		ringQ:  q,
		sk:     sk,
	}
}

func (decryptor *ckksDecryptor) DecryptNew(ciphertext *Ciphertext) (plaintext *Plaintext) {

	plaintext = NewPlaintextCKKS(decryptor.params, ciphertext.Level(), ciphertext.Scale())

	decryptor.Decrypt(ciphertext, plaintext)

	return plaintext
}

func (decryptor *ckksDecryptor) Decrypt(ciphertext *Ciphertext, plaintext *Plaintext) {

	level := utils.MinInt(ciphertext.Level(), plaintext.Level())

	plaintext.SetScale(ciphertext.Scale())

	decryptor.ringQ.CopyLvl(level, ciphertext.value[ciphertext.Degree()], plaintext.value)

	plaintext.value.Coeffs = plaintext.value.Coeffs[:ciphertext.Level()+1]

	for i := ciphertext.Degree(); i > 0; i-- {

		decryptor.ringQ.MulCoeffsMontgomeryLvl(level, plaintext.value, decryptor.sk.Value, plaintext.value)
		decryptor.ringQ.AddLvl(level, plaintext.value, ciphertext.value[i-1], plaintext.value)

		if i&7 == 7 {
			decryptor.ringQ.ReduceLvl(level, plaintext.value, plaintext.value)
		}
	}

	if (ciphertext.Degree())&7 != 7 {
		decryptor.ringQ.ReduceLvl(level, plaintext.value, plaintext.value)
	}

	plaintext.value.Coeffs = plaintext.value.Coeffs[:level+1]
}
