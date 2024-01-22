package ckks_fv

import (
	"HHESoK/ckks_integration/ring"
	"HHESoK/ckks_integration/utils"
)

// Ciphertext is *ring.Poly array representing a polynomial of degree > 0 with coefficients in R_Q.
type Ciphertext struct {
	*Element
}

// NewCiphertextFV creates a new FV ciphertext parameterized by degree, level and scale.
func NewCiphertextFV(params *Parameters, degree int) (ciphertext *Ciphertext) {
	return &Ciphertext{newCiphertextElement(params, degree)}
}

func NewCiphertextFVLvl(params *Parameters, degree int, level int) (ciphertext *Ciphertext) {
	ciphertext = &Ciphertext{&Element{}}
	ciphertext.value = make([]*ring.Poly, degree+1)
	for i := 0; i < degree+1; i++ {
		ciphertext.value[i] = ring.NewPoly(params.N(), level+1)
	}

	return ciphertext
}

// NewCiphertextFVRandom generates a new uniformly distributed FV ciphertext of degree, level and scale.
func NewCiphertextFVRandom(prng utils.PRNG, params *Parameters, degree int) (ciphertext *Ciphertext) {
	ciphertext = &Ciphertext{newCiphertextElement(params, degree)}
	populateElementRandom(prng, params, ciphertext.Element)
	return
}

// NewCiphertextCKKS creates a new CKKS Ciphertext parameterized by degree, level and scale.
func NewCiphertextCKKS(params *Parameters, degree, level int, scale float64) (ciphertext *Ciphertext) {

	ciphertext = &Ciphertext{&Element{}}

	ciphertext.value = make([]*ring.Poly, degree+1)
	for i := 0; i < degree+1; i++ {
		ciphertext.value[i] = ring.NewPoly(params.N(), level+1)
	}

	ciphertext.scale = scale
	ciphertext.isNTT = true

	return ciphertext
}

// NewCiphertextCKKSRandom generates a new uniformly distributed Ciphertext of degree, level and scale.
func NewCiphertextCKKSRandom(prng utils.PRNG, params *Parameters, degree, level int, scale float64) (ciphertext *Ciphertext) {

	ringQ, err := ring.NewRing(params.N(), params.qi[:level+1])
	if err != nil {
		panic(err)
	}

	sampler := ring.NewUniformSampler(prng, ringQ)
	ciphertext = NewCiphertextCKKS(params, degree, level, scale)
	for i := 0; i < degree+1; i++ {
		sampler.Read(ciphertext.value[i])
	}

	return ciphertext
}
