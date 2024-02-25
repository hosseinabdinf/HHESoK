package pasta

import (
	"HHESoK"
	"HHESoK/sym/pasta"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestPasta3Pack(t *testing.T) {
	for _, tc := range pasta3TestVector {
		fmt.Println(testString("PASTA-3", tc.SymParams))
		testHEPastaPack(t, tc)
	}

	//testHEPastaPack(t, pasta3TestVector[0])
}

func TestPasta4Pack(t *testing.T) {
	for _, tc := range pasta4TestVector {
		fmt.Println(testString("PASTA-4", tc.SymParams))
		testHEPastaPack(t, tc)
	}

	//testHEPastaPack(t, pasta3TestVector[0])
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

	// generates Random data for full coefficients
	fmt.Println("RandomDataGen")
	data := hePastaPack.RandomDataGen()

	// generate key stream
	fmt.Println("EncryptSymData")
	symPasta := pasta.NewPasta(tc.Key, tc.SymParams)
	symCipherTexts := symPasta.NewEncryptor().Encrypt(data)

	// create Galois keys for evaluation
	fmt.Println("GaloisKeysGen")
	hePastaPack.CreateGaloisKeys(len(symCipherTexts))

	// encrypts symmetric master key using BFV on the client side
	fmt.Println("EncryptSymKey")
	hePastaPack.EncryptSymKey(tc.Key)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, 123456789)

	// the server side tranciphering
	fmt.Println("Trancipher")
	fvCiphers := hePastaPack.Trancipher(nonce, symCipherTexts)

	fmt.Println("Flatten")
	ctRes := hePastaPack.Flatten(fvCiphers, len(symCipherTexts))

	ptRes := hePastaPack.Decrypt(ctRes)

	hePastaPack.logger.PrintDataLen(data)
	hePastaPack.logger.PrintDataLen(ptRes)
}
