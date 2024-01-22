package ckks_fv

import "HHESoK/ckks_integration/ring"

// PlaintextCKKS is is a Element with only one Poly.
type Plaintext struct {
	*Element
	value *ring.Poly
}

// PlaintextRingT represents a plaintext element in R_t.
// This is the most compact representation of a plaintext, but performing operations have the extra-cost of performing
// the scaling up by Q/t. See bfv/encoder.go for more information on plaintext types.
type PlaintextRingT Plaintext

// PlaintextMul represents a plaintext element in R_q, in NTT and Montgomery form, but without scale up by Q/t.
// A PlaintextMul is a special-purpose plaintext for efficient Ciphertext-Plaintext multiplication. However,
// other operations on plaintexts are not supported. See bfv/encoder.go for more information on plaintext types.
type PlaintextMul Plaintext

// NewPlaintext creates a new Plaintext of level level and scale scale.
func NewPlaintextCKKS(params *Parameters, level int, scale float64) *Plaintext {

	plaintext := &Plaintext{&Element{}, nil}

	plaintext.Element.value = []*ring.Poly{ring.NewPoly(params.N(), level+1)}

	plaintext.value = plaintext.Element.value[0]

	plaintext.scale = scale
	plaintext.isNTT = true

	return plaintext
}

// NewPlaintext creates and allocates a new plaintext in RingQ (multiple moduli of Q).
// The plaintext will be in RingQ and scaled by Q/t.
// Slower encoding and larger plaintext size
func NewPlaintextFV(params *Parameters) *Plaintext {
	plaintext := &Plaintext{newPlaintextElement(params), nil}
	plaintext.value = plaintext.Element.value[0]
	return plaintext
}

// NewPlaintextLvl creates and allocates a new plaintext in RingQ (multiple moduli of Q)
// of given level.
// The plaintext will be in RingQ and scaled by Q/t.
// Slower encoding and larger plaintext size
func NewPlaintextFVLvl(params *Parameters, level int) *Plaintext {
	plaintext := &Plaintext{&Element{}, nil}

	plaintext.Element.value = []*ring.Poly{ring.NewPoly(params.N(), level+1)}
	plaintext.value = plaintext.Element.value[0]

	return plaintext
}

// NewPlaintextRingT creates and allocates a new plaintext in RingT (single modulus T).
// The plaintext will be in RingT.
func NewPlaintextRingT(params *Parameters) *PlaintextRingT {

	plaintext := &PlaintextRingT{newPlaintextRingTElement(params), nil}
	plaintext.value = plaintext.Element.value[0]
	return plaintext
}

// NewPlaintextMul creates and allocates a new plaintext optimized for ciphertext x plaintext multiplication.
// The plaintext will be in the NTT and Montgomery domain of RingQ and not scaled by Q/t.
func NewPlaintextMul(params *Parameters) *PlaintextMul {
	plaintext := &PlaintextMul{newPlaintextMulElement(params), nil}
	plaintext.value = plaintext.Element.value[0]
	return plaintext
}

// NewPlaintextMulLvl creates and allocates a new plaintext optimized for ciphertext x plaintext multiplication.
// The plaintext will be in the NTT and Montgomery domain of RingQ of given level and not scaled by Q/t.
func NewPlaintextMulLvl(params *Parameters, level int) *PlaintextMul {
	plaintext := &PlaintextMul{&Element{}, nil}

	plaintext.Element.value = []*ring.Poly{ring.NewPoly(params.N(), level+1)}
	plaintext.value = plaintext.Element.value[0]

	return plaintext
}
