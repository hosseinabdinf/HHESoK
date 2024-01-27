package pasta

import (
	"HHESoK/symcips"
	"fmt"
	"reflect"
	"testing"
)

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/KeySize=%d/PlainSize=%d/CipherSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetKeySize(), p.GetPlainSize(), p.GetCipherSize(), p.GetModulus(), p.GetRounds())
}

func TestPasta3(t *testing.T) {
	logger := symcips.NewLogger(symcips.DEBUG)
	for _, tc := range pasta3TestVector {
		pastaCipher := NewPasta(tc.key, tc.params)
		encryptor := pastaCipher.NewEncryptor()
		var ciphertext symcips.Ciphertext

		t.Run("PastaEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.plaintext)
		})

		t.Run("PastaDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		t.Run(testString("Pasta", tc.params), func(t *testing.T) {
			newCiphertext := encryptor.Encrypt(tc.plaintext)
			newPlaintext := encryptor.Decrypt(newCiphertext)

			if reflect.DeepEqual(tc.plaintext, newPlaintext) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
			}
			if reflect.DeepEqual(tc.expCipherText, newCiphertext) {
				logger.PrintMessage("Got the same ciphertext, it is working fine.")
			} else {
				logger.PrintMessage("The ciphertext after ENC is different, encryption failure!")
			}
		})
	}
}

func TestPasta4(t *testing.T) {
	logger := symcips.NewLogger(symcips.DEBUG)
	for _, tc := range pasta4TestVector {
		pastaCipher := NewPasta(tc.key, tc.params)
		encryptor := pastaCipher.NewEncryptor()
		var ciphertext symcips.Ciphertext

		t.Run("PastaEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.plaintext)
		})

		t.Run("PastaDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		t.Run(testString("Pasta", tc.params), func(t *testing.T) {
			newCiphertext := encryptor.Encrypt(tc.plaintext)
			newPlaintext := encryptor.Decrypt(newCiphertext)

			if reflect.DeepEqual(tc.plaintext, newPlaintext) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
			}
			if reflect.DeepEqual(tc.expCipherText, newCiphertext) {
				logger.PrintMessage("Got the same ciphertext, it is working fine.")
			} else {
				logger.PrintMessage("The ciphertext after ENC is different, encryption failure!")
			}
		})
	}
}
