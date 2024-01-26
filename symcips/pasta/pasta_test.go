package pasta

import (
	"HHESoK/symcips"
	"fmt"
	"testing"
)

func printLog(msg string) {
	fmt.Printf("\t--- %s\n", msg)
}

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/PlainSize=%d/CipherSize=%d/KeySize=%d/Modulus=%d",
		opName, p.GetPlainSize(), p.GetCipherSize(), p.GetKeySize(), p.GetModulus())
}

func TestPasta(t *testing.T) {
	for _, tc := range decTestVector {
		pastaCipher := NewPasta(tc.key, tc.params, 3)
		encryptor := pastaCipher.NewEncryptor()
		var ciphertext symcips.Ciphertext

		t.Run("PastaEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.plaintext)
		})

		t.Run("PastaDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})
		//
		//t.Run(testString("Pasta/DecryptionTest", tc.params), func(t *testing.T) {
		//	newCiphertext := encryptor.Encrypt(tc.plaintext)
		//	newPlaintext := encryptor.Decrypt(newCiphertext)
		//
		//	if reflect.DeepEqual(tc.plaintext, newPlaintext) {
		//		printLog("Got the same plaintext, it is working fine.")
		//	} else {
		//		printLog("The plaintext after DEC is different, decryption failure!")
		//	}
		//	if reflect.DeepEqual(tc.expCipherText, newCiphertext) {
		//		printLog("Got the same ciphertext, it is working fine.")
		//	} else {
		//		printLog("The ciphertext after ENC is different, encryption failure!")
		//	}
		//})
	}
}
