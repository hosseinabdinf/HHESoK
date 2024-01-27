package hera

import (
	"HHESoK/symcips"
	"fmt"
	"testing"
)

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestHera(t *testing.T) {
	logger := symcips.NewLogger(symcips.DEBUG)
	for _, tc := range testVector {
		fmt.Println(testString("HERA", tc.params))
		heraCipher := NewHera(tc.key, tc.params)
		encryptor := heraCipher.NewEncryptor()
		var ciphertext symcips.Ciphertext

		t.Run("HeraEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.plaintext)
		})

		t.Run("HeraDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		logger.PrintDataLen(tc.key)
		logger.PrintDataLen(ciphertext)
	}
}
