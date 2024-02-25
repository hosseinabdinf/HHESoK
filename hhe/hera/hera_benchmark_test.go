package hera

import (
	"HHESoK/rtf_ckks_integration/ckks_fv"
	"HHESoK/sym/hera"
	"fmt"
	"testing"
)

func BenchmarkHera(b *testing.B) {
	// comment below loop if you want to go over each test case manually
	// it helps to get benchmark results when there's memory limit in the
	// test environment
	for _, tc := range hera.TestVector {
		// skip the test for 80-bit security
		if tc.Params.Rounds == 4 {
			continue
		}
		benchHEHera(tc, b)
	}
	// uncomment following line if you want to use manual test case
	// you can choose test cased from [0-3] 80-bit sec and [4-7] 128-bit sec
	//benchHEHera(hera.TestVector[4], b)
}

func benchHEHera(tc hera.TestContext, b *testing.B) {
	fmt.Println(testString("HERA", tc.Params))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	heHera := NewHEHera()

	var data [][]float64
	var nonces [][]byte
	var keyStream [][]uint64

	heHera.InitParams(tc.FVParamIndex, tc.Params)

	b.Run("HERA/HEKeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heHera.HEKeyGen()
		}
	})

	b.Run("HERA/HalfBootKeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heHera.HalfBootKeyGen(tc.Radix)
		}
	})

	heHera.InitHalfBootstrapper()

	heHera.InitEvaluator()

	heHera.InitCoefficients()

	if heHera.fullCoefficients {
		data = heHera.RandomDataGen(heHera.params.N())

		nonces = heHera.NonceGen(heHera.params.N())

		keyStream = make([][]uint64, heHera.params.N())
		b.Run("HERA/SymKeyStream", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for i := 0; i < heHera.params.N(); i++ {
					symHera := hera.NewHera(tc.Key, tc.Params)
					keyStream[i] = symHera.KeyStream(nonces[i])
				}
			}
		})

		heHera.DataToCoefficients(data, heHera.params.N())

		b.Run("PASTA/EncryptSymData", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				heHera.EncodeEncrypt(keyStream, heHera.params.N())
			}
		})

	} else {
		data = heHera.RandomDataGen(heHera.params.Slots())

		nonces = heHera.NonceGen(heHera.params.Slots())

		keyStream = make([][]uint64, heHera.params.Slots())
		b.Run("HERA/SymKeyStream", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for i := 0; i < heHera.params.Slots(); i++ {
					symHera := hera.NewHera(tc.Key, tc.Params)
					keyStream[i] = symHera.KeyStream(nonces[i])
				}
			}
		})

		heHera.DataToCoefficients(data, heHera.params.Slots())

		b.Run("PASTA/EncryptSymData", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				heHera.EncodeEncrypt(keyStream, heHera.params.Slots())
			}
		})
	}

	heHera.ScaleUp()

	// FV Key Stream, encrypts symmetric key stream using BFV on the client side
	b.Run("HERA/EncSymKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = heHera.InitFvHera()
			heHera.EncryptSymKey(tc.Key)
		}
	})

	// get BFV key stream using encrypted symmetric key, nonce, and counter on the server side
	var fvKeyStreams []*ckks_fv.Ciphertext
	b.Run("HERA/FVKeyStream", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fvKeyStreams = heHera.GetFvKeyStreams(nonces)
		}
	})

	heHera.ScaleCiphertext(fvKeyStreams)

	b.Run("Rubato/HalfBoot", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = heHera.HalfBoot()
		}
	})
}
