package rubato

import (
	"HHESoK/rtf_ckks_integration/ckks_fv"
	"HHESoK/sym/rubato"
	"crypto/rand"
	"fmt"
	"testing"
)

func BenchmarkRubato(b *testing.B) {
	// comment below loop if you want to go over each test case manually
	// it helps to get benchmark results when there's memory limit in the
	// test environment
	for _, tc := range rubato.TestsVector {
		benchHERubato(tc, b)
	}
	// uncomment following line if you want to use manual test case
	// you can choose test cased from [0-2]
	// benchHERubato(rubato.TestsVector[2], b)
}

func benchHERubato(tc rubato.TestContext, b *testing.B) {
	fmt.Println(testString("Rubato", tc.Params))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	heRubato := NewHERubato()

	heRubato.InitParams(tc.FVParamIndex, tc.Params, len(tc.Plaintext))

	b.Run("Rubato/HEKeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heRubato.HEKeyGen()
		}
	})

	b.Run("Rubato/HalfBootKeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heRubato.HalfBootKeyGen()
		}
	})

	heRubato.InitHalfBootstrapper()

	heRubato.InitEvaluator()

	heRubato.InitCoefficients()

	// use the plaintext data from test vector or generate Random
	data := heRubato.RandomDataGen()

	// need an array of 8-byte nonce for each block of data
	nonces := heRubato.NonceGen()

	// need an 8-byte counter
	counter := make([]byte, 8)
	_, _ = rand.Read(counter)

	// generate key stream using plain rubato
	keyStream := make([][]uint64, heRubato.N)

	b.Run("Rubato/SymKeyStream", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for i := 0; i < heRubato.N; i++ {
				symRub := rubato.NewRubato(tc.Key, tc.Params)
				keyStream[i] = symRub.KeyStream(nonces[i], counter)
			}
		}
	})

	// data to coefficients
	heRubato.DataToCoefficients(data)

	b.Run("PASTA/EncryptSymData", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heRubato.EncodeEncrypt(keyStream)
		}
	})

	heRubato.ScaleUp()

	// FV Key Stream, encrypts symmetric key stream using BFV on the client side
	b.Run("Rubato/EncSymKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = heRubato.InitFvRubato()
			heRubato.EncryptSymKey(tc.Key)
		}
	})

	// get BFV key stream using encrypted symmetric key, nonce, and counter on the server side
	var fvKeyStreams []*ckks_fv.Ciphertext
	b.Run("Rubato/FVKeyStream", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fvKeyStreams = heRubato.GetFvKeyStreams(nonces, counter)
		}
	})

	heRubato.ScaleCiphertext(fvKeyStreams)

	// half bootstrapping
	b.Run("Rubato/HalfBoot", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = heRubato.HalfBoot()
		}
	})
}
