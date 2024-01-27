package hera

import (
	"HHESoK/ckks_integration/ckks_fv"
	"HHESoK/symcips"
)

type TestCase int

const (
	ENC TestCase = iota
	DEC
)

const (
	HR80F = iota
	HR80S
	HR80AF
	HR80AS
)

const (
	HR128F = iota
	HR128S
	HR128AF
	HR128AS
)

type TestContext struct {
	tc         TestCase
	params     Parameter
	key        symcips.Key
	plaintext  symcips.Plaintext
	ciphertext symcips.Ciphertext
}

// Test Vectors
var testVector = []TestContext{
	//	HERA 80 bits security
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR80F].PlainModulus,
			Rounds:    4,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR80S].PlainModulus,
			Rounds:    4,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR80AF].PlainModulus,
			Rounds:    4,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR80AS].PlainModulus,
			Rounds:    4,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
	//	HERA 128 bits security
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR128F].PlainModulus,
			Rounds:    5,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR128S].PlainModulus,
			Rounds:    5,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR128AF].PlainModulus,
			Rounds:    5,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: 16,
			Modulus:   ckks_fv.RtFHeraParams[HR128AS].PlainModulus,
			Rounds:    5,
		},
		key:        symcips.Key{},
		plaintext:  symcips.Plaintext{},
		ciphertext: symcips.Ciphertext{},
	},
}
