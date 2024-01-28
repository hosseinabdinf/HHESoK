package hera

import (
	"HHESoK/symcips"
	"fmt"
	"testing"
)

func BenchmarkHera(b *testing.B) {
	for _, tc := range testVector {
		benchmarkHera(&tc, b)
	}
}

func benchmarkHera(tc *TestContext, b *testing.B) {
	fmt.Println(testString("HERA", tc.params))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	var heraCipher Hera
	var encryptor Encryptor
	var newCiphertext symcips.Ciphertext

	b.Run("HERA/NewHera", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			heraCipher = NewHera(tc.key, tc.params)
		}
	})

	b.Run("HERA/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = heraCipher.NewEncryptor()
		}
	})

	b.Run("HERA/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			newCiphertext = encryptor.Encrypt(tc.plaintext)
		}
	})

	b.Run("HERA/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor.Decrypt(newCiphertext)
		}
	})
}
