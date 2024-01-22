package ckks_fv

import (
	"HHESoK/ckks_integration/ring"
)

// MFVDecryptor is an interface for decryptors
type MFVDecryptor interface {
	// DecryptNew decrypts the input ciphertext and returns the result on a new
	// plaintext.
	DecryptNew(ciphertext *Ciphertext) *Plaintext

	// Decrypt decrypts the input ciphertext and returns the result on the
	// provided receiver plaintext.
	Decrypt(ciphertext *Ciphertext, plaintext *Plaintext)
}

// mfvDecryptor is a structure used to decrypt ciphertexts. It stores the secret-key.
type mfvDecryptor struct {
	params   *Parameters
	ringQ    *ring.Ring
	sk       *SecretKey
	polypool *ring.Poly
}

// NewMFVDecryptor creates a new Decryptor from the parameters with the secret-key
// given as input.
func NewMFVDecryptor(params *Parameters, sk *SecretKey) MFVDecryptor {

	var ringQ *ring.Ring
	var err error
	if ringQ, err = ring.NewRing(params.N(), params.qi); err != nil {
		panic(err)
	}

	return &mfvDecryptor{
		params:   params.Copy(),
		ringQ:    ringQ,
		sk:       sk,
		polypool: ringQ.NewPoly(),
	}
}

func (decryptor *mfvDecryptor) DecryptNew(ciphertext *Ciphertext) *Plaintext {
	level := ciphertext.Level()
	p := NewPlaintextFVLvl(decryptor.params, level)
	decryptor.Decrypt(ciphertext, p)
	return p
}

func (decryptor *mfvDecryptor) Decrypt(ciphertext *Ciphertext, p *Plaintext) {

	if ciphertext.Level() != p.Level() {
		panic("ciphertext and p should have the same level")
	}

	ringQ := decryptor.ringQ
	tmp := decryptor.polypool

	level := p.Level()
	ringQ.NTTLazyLvl(level, ciphertext.value[ciphertext.Degree()], p.value)

	for i := ciphertext.Degree(); i > 0; i-- {
		ringQ.MulCoeffsMontgomeryLvl(level, p.value, decryptor.sk.Value, p.value)
		ringQ.NTTLazyLvl(level, ciphertext.value[i-1], tmp)
		ringQ.AddLvl(level, p.value, tmp, p.value)

		if i&3 == 3 {
			ringQ.ReduceLvl(level, p.value, p.value)
		}
	}

	if (ciphertext.Degree())&3 != 3 {
		ringQ.ReduceLvl(level, p.value, p.value)
	}

	ringQ.InvNTTLvl(level, p.value, p.value)
}
