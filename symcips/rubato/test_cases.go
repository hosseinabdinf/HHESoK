package rubato

import (
	"HHESoK/ckks_integration/ckks_fv"
	"HHESoK/symcips"
)

type TestCase int

const (
	ENC TestCase = iota
	DEC
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
	{
		tc: ENC,
		params: Parameter{
			BlockSize: ckks_fv.RubatoParams[ckks_fv.RUBATO128S].Blocksize,
			Modulus:   ckks_fv.RubatoParams[ckks_fv.RUBATO128S].PlainModulus,
			Rounds:    ckks_fv.RubatoParams[ckks_fv.RUBATO128S].NumRound,
			Sigma:     ckks_fv.RubatoParams[ckks_fv.RUBATO128S].Sigma,
		},
		key: symcips.Key{
			0x1c765bc, 0x2a40364, 0x15edec7, 0xa75d18,
			0x40feac, 0x24cd598, 0x3c7cab2, 0x1b3e732,
			0x25e4ea3, 0xcbeeea, 0x302a99a, 0x157e6aa,
			0x345cd89, 0x2b7aaaf, 0xcf7147, 0x3c09951,
		},
		plaintext: symcips.Plaintext{
			0xc42d4a, 0x288e8a2, 0x953716, 0x1e02031,
			0x1d1c338, 0x3cc51d8, 0x3869d27, 0x28ea11d,
			0x24c4861, 0xf9d800, 0xaae535, 0x2dcee2d,
			0x2af3dcb, 0x35bc913, 0x1a440b8, 0x1b5497d,
		},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: ckks_fv.RubatoParams[ckks_fv.RUBATO128M].Blocksize,
			Modulus:   ckks_fv.RubatoParams[ckks_fv.RUBATO128M].PlainModulus,
			Rounds:    ckks_fv.RubatoParams[ckks_fv.RUBATO128M].NumRound,
			Sigma:     ckks_fv.RubatoParams[ckks_fv.RUBATO128M].Sigma,
		},
		key: symcips.Key{
			0x1c765bc, 0x2a40364, 0x15edec7, 0xa75d18,
			0x40feac, 0x24cd598, 0x3c7cab2, 0x1b3e732,
			0x25e4ea3, 0xcbeeea, 0x302a99a, 0x157e6aa,
			0x345cd89, 0x2b7aaaf, 0xcf7147, 0x3c09951,
		},
		plaintext: symcips.Plaintext{
			0xc42d4a, 0x288e8a2, 0x953716, 0x1e02031,
			0x1d1c338, 0x3cc51d8, 0x3869d27, 0x28ea11d,
			0x24c4861, 0xf9d800, 0xaae535, 0x2dcee2d,
			0x2af3dcb, 0x35bc913, 0x1a440b8, 0x1b5497d,
		},
		ciphertext: symcips.Ciphertext{},
	},
	{
		tc: ENC,
		params: Parameter{
			BlockSize: ckks_fv.RubatoParams[ckks_fv.RUBATO128L].Blocksize,
			Modulus:   ckks_fv.RubatoParams[ckks_fv.RUBATO128L].PlainModulus,
			Rounds:    ckks_fv.RubatoParams[ckks_fv.RUBATO128L].NumRound,
			Sigma:     ckks_fv.RubatoParams[ckks_fv.RUBATO128L].Sigma,
		},
		key: symcips.Key{
			0x1c765bc, 0x2a40364, 0x15edec7, 0xa75d18,
			0x40feac, 0x24cd598, 0x3c7cab2, 0x1b3e732,
			0x25e4ea3, 0xcbeeea, 0x302a99a, 0x157e6aa,
			0x345cd89, 0x2b7aaaf, 0xcf7147, 0x3c09951,
		},
		plaintext: symcips.Plaintext{
			0xc42d4a, 0x288e8a2, 0x953716, 0x1e02031,
			0x1d1c338, 0x3cc51d8, 0x3869d27, 0x28ea11d,
			0x24c4861, 0xf9d800, 0xaae535, 0x2dcee2d,
			0x2af3dcb, 0x35bc913, 0x1a440b8, 0x1b5497d,
		},
		ciphertext: symcips.Ciphertext{},
	},
}
