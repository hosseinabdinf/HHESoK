package hera

import "HHESoK/symcips"

type TestCase int

const (
	MAT TestCase = iota
	DEC
	USECASE
	PREP
)

const (
	PreSetSeed       = true
	NumMatMulSquares = 3
	LastSquare       = false
)

type TestContext struct {
	N             uint64
	tc            TestCase
	round         int
	params        Parameter
	key           symcips.Key
	plaintext     symcips.Plaintext
	expCipherText symcips.Ciphertext
}
