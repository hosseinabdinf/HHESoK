package pasta

import (
	"HHESoK"
	"HHESoK/sym/pasta"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestPasta3Pack(t *testing.T) {
	//for _, tc := range pasta3TestVector {
	//  fmt.Println(testString("PASTA-3", tc.SymParams))
	//	testHEPasta(t, tc)
	//}

	testHEPastaPack(t, pasta3TestVector[0])
}

func TestPasta4Pack(t *testing.T) {
	//logger := HHESoK.NewLogger(HHESoK.DEBUG)
	//for _, tc := range pasta4TestVector {
	//	fmt.Println(testString("PASTA-4", tc.SymParams))
	//	logger.PrintDataLen(tc.Key)
	//	testHEPasta(t, tc)
	//}
	testHEPastaPack(t, pasta3TestVector[0])
}

func testHEPastaPack(t *testing.T, tc TestContext) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	logger.PrintDataLen(tc.Key)

	hePastaPack := NewHEPastaPack()

	fmt.Println("InitParams")
	hePastaPack.InitParams(tc.Params, tc.SymParams)

	fmt.Println("HEKeyGen")
	hePastaPack.HEKeyGen()

	fmt.Println("InitFvPasta")
	_ = hePastaPack.InitFvPasta()

	fmt.Println("InitCoefficients")
	hePastaPack.InitCoefficients()

	fmt.Println("RandomDataGen")
	// use the plaintext data from test vector or generate Random ones for full coefficients
	data := hePastaPack.RandomDataGen()

	fmt.Println("InitEvaluator")
	hePastaPack.InitEvaluator(tc.ExpCipherText)

	// need an array of 8-byte nonce for each block of data
	nonces := hePastaPack.NonceGen()

	// need an 8-byte counter
	counter := make([]byte, 8)

	// generate key stream
	fmt.Println("KeyStreamGen")
	keyStream := make([][]uint64, hePastaPack.bfvParams.N())
	for i := 0; i < hePastaPack.bfvParams.N(); i++ {
		symPasta := pasta.NewPasta(tc.Key, tc.SymParams)
		binary.BigEndian.PutUint64(counter, uint64(i))
		keyStream[i] = symPasta.KeyStream(nonces[i], counter)
	}

	fmt.Println("DataToCoefficients")
	hePastaPack.DataToCoefficients(data)

	// simulate the data encryption on client side and encode the result into polynomial representations
	hePastaPack.EncodeEncrypt(keyStream)

	// encrypts symmetric master key using BFV on the client side
	fmt.Println("EncryptSymKey")
	hePastaPack.EncryptSymKey(tc.Key)

	////// the server side
	fmt.Println("Trancipher")
	hePastaPack.Trancipher(nonces, tc.ExpCipherText)

}
