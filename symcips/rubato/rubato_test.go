package rubato

import (
	"HHESoK/ckks_integration/utils"
	"HHESoK/symcips"
	"fmt"
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
	for _, tc := range testVector {
		//testInstance(&tc, t)
		simpleKeyGen(tc.params.GetBlockSize())
	}
}

func TestGenerateDummyData(t *testing.T) {
	fmt.Println(">  Setup the parameters")
	for _, tc := range testVector {
		outputSize := tc.params.GetBlockSize() - 4
		N := 16
		delta := float64(tc.params.GetModulus()) / float64(N)
		// it is a Matrix of 12*16 elements
		data := getRandomData(N, outputSize)
		//fmt.Println(data)

		// create a Rubato instance with key and params
		rubatoCipher := NewRubato(tc.key, tc.params)
		encryptor := rubatoCipher.NewEncryptor()

		// scale data to save as []uint64
		ciphertext := make([]symcips.Ciphertext, outputSize)
		newPlaintext := make([]symcips.Plaintext, outputSize)
		for s := 0; s < outputSize; s++ {
			plaintext := func() []uint64 {
				result := make([]uint64, len(data[s]))
				for i, v := range data[s] {
					result[i] = symcips.ScaleUp(v, delta)
				}
				return result
			}()
			fmt.Println("original: ", data[0])
			//symcips.Uint64ToHex(plaintext)
			fmt.Println(">  Encrypt() the data[", s, "]")
			ciphertext[s] = encryptor.Encrypt(plaintext)
			fmt.Println("Cipher: ", ciphertext[s])
			newPlaintext[s] = encryptor.Decrypt(ciphertext[s])
			nData := func() []float64 {
				res := make([]float64, len(newPlaintext[s]))
				for j, el := range newPlaintext[s] {
					res[j] = symcips.ScaleDown(el, delta)
				}
				return res
			}()
			fmt.Println("new Data: ", nData)
		}
	}
}

func testInstance(tc *TestContext, t *testing.T) {
	t.Run(testString("Rubato", tc.params), func(t *testing.T) {
		//rubatoCipher := NewRubato(tc.key, tc.params)
		//encryptor := rubatoCipher.NewEncryptor()
		//newCiphertext := encryptor.Encrypt(tc.plaintext)
		//newPlaintext := encryptor.Decrypt(newCiphertext)
		//
		//if reflect.DeepEqual(tc.plaintext, newPlaintext) {
		//	printLog("Got the same plaintext, it is working fine.")
		//} else {
		//	printLog("The plaintext after DEC is different, decryption failure!")
		//}
		//if reflect.DeepEqual(tc.ciphertext, newCiphertext) {
		//	printLog("Got the same ciphertext, it is working fine.")
		//} else {
		//	printLog("The ciphertext after ENC is different, encryption failure!")
		//}
	})
}

func getRandomData(N int, outSize int) (data [][]float64) {
	// Get random data in [0, 1]
	fmt.Println(">  Data generation")
	for s := 0; s < outSize; s++ {
		data[s] = make([]float64, N)
		for i := 0; i < N; i++ {
			data[s][i] = utils.RandFloat64(0, 1)
		}
	}
	return
}

func simpleKeyGen(blockSize int) {
	// Key generation
	key := make([]uint64, blockSize)
	for i := 0; i < blockSize; i++ {
		key[i] = uint64(i + 1) // Use (1, ..., 16) for testing
	}
	symcips.Uint64ToHex(key)
}
