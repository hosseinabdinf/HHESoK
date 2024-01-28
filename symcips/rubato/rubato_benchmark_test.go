package rubato

import (
	"HHESoK"
	"fmt"
	"testing"
)

func BenchmarkRubato(b *testing.B) {
	for _, tc := range testVector {
		benchmarkRubato(&tc, b)
	}
}

func benchmarkRubato(tc *TestContext, b *testing.B) {
	fmt.Println(testString("Rubato", tc.params))
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	var rubatoCipher Rubato
	var encryptor Encryptor
	var newCiphertext HHESoK.Ciphertext

	b.Run("Rubato/NewRubato", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rubatoCipher = NewRubato(tc.key, tc.params)
		}
	})

	b.Run("Rubato/NewEncryptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor = rubatoCipher.NewEncryptor()
		}
	})

	b.Run("Rubato/Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			newCiphertext = encryptor.Encrypt(tc.plaintext)
		}
	})

	b.Run("Rubato/Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptor.Decrypt(newCiphertext)
		}
	})
}
