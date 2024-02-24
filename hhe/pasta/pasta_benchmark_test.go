package pasta

import (
	"HHESoK/sym/pasta"
	"fmt"
	"testing"
)

func BenchmarkPasta3(b *testing.B) {
	// comment below loop if you want to go over each test case manually
	// it helps to get benchmark results when there's memory limit in the
	// test environment
	for _, tc := range pasta3TestVector {
		benchHEPasta(tc, b)
	}
	// uncomment following line if you want to use manual test case
	// you can choose test cased from [0-3] 80-bit sec and [4-7] 128-bit sec
	//benchHEPasta(hera.TestVector[4], b)
}

func benchHEPasta(tc TestContext, b *testing.B) {
	fmt.Println(testString("PASTA", tc.SymParams))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	hePasta := NewHEPasta()

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()

	nonce := uint64(123456789)
	keyStream := make([][]uint64, hePasta.bfvParams.N())

	symPasta := pasta.NewPasta(tc.Key, tc.SymParams)

	b.Run("PASTA/KeyStreamGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for i := 0; i < hePasta.bfvParams.N(); i++ {
				keyStream[i] = symPasta.KeyStream(nonce, uint64(i))
			}
		}
	})

	_ = hePasta.InitFvPasta()
	b.Run("PASTA/EncSymKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hePasta.EncryptSymKey(tc.Key)
		}
	})

}
