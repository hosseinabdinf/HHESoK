package pasta

import (
	"HHESoK/symcips"
	"testing"
)

func BenchmarkPasta(b *testing.B) {
	for _, decTest := range decTestVector {
		benchmarkDecryption(&decTest, b)
	}
}

func benchmarkDecryption(tc *TestContext, b *testing.B) {
	testString("Pasta/DecryptionTest", tc.params)
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	var pastaCipher Pasta
	var encryptor Encryptor
	var newCiphertext symcips.Ciphertext
	b.Run("Pasta/NewPasta", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pastaCipher = NewPasta(tc.key, tc.params, 3)
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
