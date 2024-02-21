package hera

import (
	"HHESoK"
	"fmt"
	"testing"
)

func BenchmarkHera(b *testing.B) {
	for _, tc := range TestVector {
		benchmarkHera(&tc, b)
	}
}

func benchmarkHera(tc *TestContext, b *testing.B) {
	fmt.Println(testString("HERA", tc.Params))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	var heraCipher Hera
	var encryptor Encryptor
	var newCiphertext HHESoK.Ciphertext

	b.Run("HERA/NewHera", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heraCipher = NewHera(tc.Key, tc.Params)
		}
	})

	b.Run("HERA/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = heraCipher.NewEncryptor()
		}
	})

	b.Run("HERA/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			newCiphertext = encryptor.Encrypt(tc.Plaintext)
		}
	})

	b.Run("HERA/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor.Decrypt(newCiphertext)
		}
	})
}
