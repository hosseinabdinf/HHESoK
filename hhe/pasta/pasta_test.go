package pasta

import (
	"HHESoK"
	"HHESoK/sym/pasta"
	"encoding/binary"
	"fmt"
	"testing"
)

func testString(opName string, p pasta.Parameter) string {
	return fmt.Sprintf("%s/KeySize=%d/PlainSize=%d/CipherSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetKeySize(), p.GetPlainSize(), p.GetCipherSize(), p.GetModulus(), p.GetRounds())
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
	//testHEPasta(t, pasta3TestVector[0])
}

func testHEPasta(t *testing.T, tc TestContext) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	logger.PrintDataLen(tc.Key)

	hePasta := NewHEPasta()

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()

	_ = hePasta.InitFvPasta()

	hePasta.InitEvaluator(tc.ExpCipherText)

	//encrypts symmetric master key using BFV on the client side
	hePasta.EncryptSymKey(tc.Key)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	// the server side
	fvCiphers := hePasta.Trancipher(nonce, tc.ExpCipherText)

	hePasta.Decrypt(fvCiphers[0])
}
