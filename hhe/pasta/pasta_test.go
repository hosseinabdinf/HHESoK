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
	//nonce := uint64(123456789)

	hePasta := NewHEPasta()

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()

}
