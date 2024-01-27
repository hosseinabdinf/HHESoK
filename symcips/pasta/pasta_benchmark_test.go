package pasta

import (
	"HHESoK/symcips"
	"fmt"
	"testing"
)

func BenchmarkPasta3(b *testing.B) {
	for _, tc := range pasta3TestVector {
		benchmarkPasta(&tc, b)
	}
}

func BenchmarkPasta4(b *testing.B) {
	for _, tc := range pasta4TestVector {
		benchmarkPasta(&tc, b)
	}
}

func benchmarkPasta(tc *TestContext, b *testing.B) {
	fmt.Println(testString("Pasta", tc.params))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	var pastaCipher Pasta
	var encryptor Encryptor
	var newCiphertext symcips.Ciphertext
	b.Run("Pasta/NewPasta", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pastaCipher = NewPasta(tc.key, tc.params)
		}
	})

	b.Run("Pasta/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = pastaCipher.NewEncryptor()
		}
	})

	b.Run("Pasta/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			newCiphertext = encryptor.Encrypt(tc.plaintext)
		}
	})

	b.Run("Pasta/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor.Decrypt(newCiphertext)
		}
	})

}
