package pasta

import (
	"HHESoK/sym/pasta"
	"encoding/binary"
	"fmt"
	"testing"
)

func testString(opName string, p pasta.Parameter) string {
	return fmt.Sprintf("%s/KeySize=%d/PlainSize=%d/CipherSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetKeySize(), p.GetBlockSize(), p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestPasta3(t *testing.T) {
	for _, tc := range pasta3TestVector {
		fmt.Println(testString("PASTA-3", tc.SymParams))
		testHEPasta(t, tc)
	}
	//testHEPasta(t, pasta3TestVector[0])
}

func TestPasta4(t *testing.T) {
	for _, tc := range pasta4TestVector {
		fmt.Println(testString("PASTA-4", tc.SymParams))
		testHEPasta(t, tc)
	}
	//testHEPasta(t, pasta4TestVector[0])
}

func testHEPasta(t *testing.T, tc TestContext) {
	hePasta := NewHEPasta()
	lg := hePasta.logger
	lg.PrintDataLen(tc.Key)

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	_ = hePasta.InitFvPasta()
	lg.PrintMemUsage("InitFvPasta")

	hePasta.CreateGaloisKeys(len(tc.ExpCipherText))
	lg.PrintMemUsage("CreateGaloisKeys")

	//encrypts symmetric master key using BFV on the client side
	hePasta.EncryptSymKey(tc.Key)
	lg.PrintMemUsage("EncryptSymKey")

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	// the server side
	fvCiphers := hePasta.Trancipher(nonce, tc.ExpCipherText)
	lg.PrintMemUsage("Trancipher")

	hePasta.Decrypt(fvCiphers[0])
	lg.PrintMemUsage("Decrypt")
}
