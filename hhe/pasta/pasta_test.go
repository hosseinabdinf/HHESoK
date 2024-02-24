package pasta

import (
	"HHESoK"
	"HHESoK/sym/pasta"
	"fmt"
	"testing"
)

func testString(opName string, p pasta.Parameter) string {
	return fmt.Sprintf("%s/KeySize=%d/PlainSize=%d/CipherSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetKeySize(), p.GetPlainSize(), p.GetCipherSize(), p.GetModulus(), p.GetRounds())
}

func TestPasta3(t *testing.T) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	for _, tc := range pasta3TestVector {
		fmt.Println(testString("PASTA-3", tc.SymParams))
		logger.PrintDataLen(tc.Key)
		testHEPasta(t, tc)
	}
}

func TestPasta4(t *testing.T) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	for _, tc := range pasta4TestVector {
		fmt.Println(testString("PASTA-4", tc.SymParams))
		logger.PrintDataLen(tc.Key)
		testHEPasta(t, tc)
	}
}

func testHEPasta(t *testing.T, tc TestContext) {
	hePasta := NewHEPasta()

	fmt.Println("InitParams")
	hePasta.InitParams(tc.Params, tc.SymParams)

	fmt.Println("HEKeyGen")
	hePasta.HEKeyGen()

	fmt.Println("InitFvPasta")
	_ = hePasta.InitFvPasta()

	fmt.Println("InitEvaluator")
	hePasta.InitEvaluator(tc.ExpCipherText)

	fmt.Println("InitCoefficients")
	hePasta.InitCoefficients()

	fmt.Println("RandomDataGen")
	// use the plaintext data from test vector or generate Random ones for full coefficients
	data := hePasta.RandomDataGen()

	// generate key stream
	nonce := uint64(123456789)
	fmt.Println("KeyStreamGen")
	keyStream := make([][]uint64, hePasta.bfvParams.N())
	for i := 0; i < hePasta.bfvParams.N(); i++ {
		symPasta := pasta.NewPasta(tc.Key, tc.SymParams)
		keyStream[i] = symPasta.KeyStream(nonce, uint64(i))
	}

	fmt.Println("DataToCoefficients")
	hePasta.DataToCoefficients(data)

	// simulate the data encryption on client side and encode the result into polynomial representations
	hePasta.EncodeEncrypt(keyStream)

	// encrypts symmetric master key using BFV on the client side
	fmt.Println("EncryptSymKey")
	hePasta.EncryptSymKey(tc.Key)

	// the server side
	fmt.Println("Trancipher")
	hePasta.Trancipher(nonce, tc.ExpCipherText)

	// encrypts symmetric master key using BFV on the client side
	fmt.Println("EncryptSymKey")
	hePasta.EncryptSymKeyPack(tc.Key)

	// the server side
	fmt.Println("Trancipher")
	hePasta.TrancipherPack(nonce, data)

}
