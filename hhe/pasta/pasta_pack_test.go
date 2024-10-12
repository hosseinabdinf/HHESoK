package pasta

import (
	"HHESoK/sym/pasta"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestPasta3Pack(t *testing.T) {
	//for _, tc := range pasta3TestVector {
	//	fmt.Println(testString("PASTA-3", tc.SymParams))
	//	testHEPastaPack(t, tc)
	//}
	testHEPastaPack(t, pasta3TestVector[0])
}

func TestPasta4Pack(t *testing.T) {
	for _, tc := range pasta4TestVector {
		fmt.Println(testString("PASTA-4", tc.SymParams))
		testHEPastaPack(t, tc)
	}
	//testHEPastaPack(t, pasta4TestVector[0])
}

func testHEPastaPack(t *testing.T, tc TestContext) {
	hePastaPack := NewHEPastaPack()
	lg := hePastaPack.logger
	lg.PrintDataLen(tc.Key)

	hePastaPack.InitParams(tc.Params, tc.SymParams)

	hePastaPack.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	_ = hePastaPack.InitFvPasta()
	lg.PrintMemUsage("InitFvPasta")

	// generates Random data for full coefficients
	data := hePastaPack.RandomDataGen()
	lg.PrintMemUsage("RandomDataGen")

	// generate key stream
	symPasta := pasta.NewPasta(tc.Key, tc.SymParams)
	symCiphertexts := symPasta.NewEncryptor().Encrypt(data)
	lg.PrintMemUsage("EncryptSymData")

	// create Galois keys for evaluation
	hePastaPack.CreateGaloisKeys(len(symCiphertexts))
	lg.PrintMemUsage("CreateGaloisKeys")

	// encrypts symmetric master key using BFV on the client side
	hePastaPack.EncryptSymKey(tc.Key)
	lg.PrintMemUsage("EncryptSymKey")

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, 123456789)

	// the server side tranciphering
	fvCiphers := hePastaPack.Trancipher(nonce, symCiphertexts)
	lg.PrintMemUsage("Transcipher")

	ctRes := hePastaPack.Flatten(fvCiphers, len(symCiphertexts))
	lg.PrintMemUsage("Flatten")

	ptRes := hePastaPack.Decrypt(ctRes)
	lg.PrintMemUsage("Decrypt")

	hePastaPack.logger.PrintDataLen(data)
	hePastaPack.logger.PrintDataLen(ptRes)
}
