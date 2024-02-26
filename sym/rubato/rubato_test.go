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
	for _, tc := range TestsVector {
		fmt.Println(testString("Rubato", tc.Params))
		rubatoCipher := NewRubato(tc.Key, tc.Params)
		encryptor := rubatoCipher.NewEncryptor()
		var ciphertext HHESoK.Ciphertext

		t.Run("RubatoEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.Plaintext)
			logger.PrintMemUsage("RubatoEncryptionTest")
		})

		t.Run("RubatoDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		logger.PrintDataLen(tc.Key)
		logger.PrintDataLen(ciphertext)
	}
}
