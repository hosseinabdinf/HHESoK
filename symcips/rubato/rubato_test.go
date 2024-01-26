package rubato

import (
	"HHESoK/ckks_integration/utils"
	"HHESoK/symcips"
	"fmt"
	"reflect"
	"testing"
)

func printLog(msg string) {
	fmt.Printf("\t--- %s\n", msg)
}

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d/Sigma=%f",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds(), p.GetSigma())
}

func TestRubato(t *testing.T) {
	for _, test := range testVector {
		testInstance(&test, t)
	}
}

func TestGenerateDummyData(t *testing.T) {
	fmt.Println(">  Setup the parameters")
	for _, test := range testVector {
		outputSize := test.params.GetBlockSize() - 4

		fmt.Println(">  Data generation")
		// Get random data in [0, 1]
		// it is a Matrix of 12*16 elements
		N := 16
		data := make([][]float64, outputSize)
		for s := 0; s < outputSize; s++ {
			data[s] = make([]float64, N)
			for i := 0; i < N; i++ {
				data[s][i] = utils.RandFloat64(0, 1)
			}
		}
		//fmt.Println(data)

		// create a Rubato instance with key and params
		rubatoCipher := NewRubato(test.key, test.params)
		encryptor := rubatoCipher.NewEncryptor()

		// scale data to save as []uint64
		ciphertext := make([]symcips.Ciphertext, outputSize)
		for s := 0; s < outputSize; s++ {
			plaintext := func() []uint64 {
				result := make([]uint64, len(data[s]))
				for i, v := range data[s] {
					result[i] = symcips.ScaleUpToModulus(v, test.params.GetModulus())
				}
				return result
			}()
			//symcips.Uint64ToHex(plaintext)
			fmt.Println(">  Encrypt() the data[", s, "]")
			ciphertext[s] = encryptor.Encrypt(plaintext)
		}
	}
}

func testInstance(tc *TestContext, t *testing.T) {
	t.Run(testString("Rubato", tc.params), func(t *testing.T) {
		rubatoCipher := NewRubato(tc.key, tc.params)
		encryptor := rubatoCipher.NewEncryptor()
		newCiphertext := encryptor.Encrypt(tc.plaintext)
		newPlaintext := encryptor.Decrypt(newCiphertext)

		if reflect.DeepEqual(tc.plaintext, newPlaintext) {
			printLog("Got the same plaintext, it is working fine.")
		} else {
			printLog("The plaintext after DEC is different, decryption failure!")
		}
		if reflect.DeepEqual(tc.ciphertext, newCiphertext) {
			printLog("Got the same ciphertext, it is working fine.")
		} else {
			printLog("The ciphertext after ENC is different, encryption failure!")
		}
	})
}
