package rubato

import (
	"HHESoK"
	"fmt"
	"testing"
)

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d/Sigma=%f",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds(), p.GetSigma())
}

func TestRubato(t *testing.T) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	for _, tc := range testVector {
		fmt.Println(testString("Rubato", tc.params))
		rubatoCipher := NewRubato(tc.key, tc.params)
		encryptor := rubatoCipher.NewEncryptor()
		var ciphertext HHESoK.Ciphertext

		t.Run("RubatoEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.plaintext)
		})

		t.Run("RubatoDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		logger.PrintDataLen(tc.key)
		logger.PrintDataLen(ciphertext)
	}
}
