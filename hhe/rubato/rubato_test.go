package rubato

import (
	"HHESoK"
	ckks "HHESoK/ckks_integration/ckks_fv"
	"HHESoK/symcips/rubato"
	"crypto/rand"
	"fmt"
	"math"
	"testing"
)

func testString(opName string, p rubato.Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d/Sigma=%f",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds(), p.GetSigma())
	//return "nil"
}

func TestRubato(t *testing.T) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	for _, tc := range rubato.TestsVector {
		fmt.Println(testString("Rubato", tc.Params))
		logger.PrintDataLen(tc.Key)
		testHERubato(t, tc)
	}
}

func testHERubato(t *testing.T, tc rubato.TestContext) {
	var heRubato HERubato
	heRubato.InitParams(ckks.RUBATO128S, tc.Params, len(tc.Plaintext))

	heRubato.HEKeyGen()

	heRubato.HalfBootKeyGen()

	heRubato.InitHalfBootstrapper()

	heRubato.InitEvaluator()

	heRubato.InitCoefficients()

	// todo: use the plaintext data from test vector
	data := heRubato.RandomDataGen()

	// todo: need an array of 8-byte nonces for each data
	nonces := heRubato.NonceGen()

	//todo: need a 8-byte counter
	counter := make([]byte, 8)
	rand.Read(counter)

	// todo: generate keystream using plain rubato
	keystream := make([][]uint64, heRubato.N)
	for i := 0; i < heRubato.N; i++ {
		symRub := rubato.NewRubato(tc.Key, tc.Params)
		keystream[i] = symRub.KeyStream(nonces[i], counter)
	}

	// data to coefficients
	heRubato.DataToCoefficients(data)

	heRubato.EncodeEncrypt(keystream)

	heRubato.ScaleUp()

	// FV Keystream
	_ = heRubato.InitFvRubato()
	heRubato.EncryptSymKey(tc.Key)

	fvKeyStreams := heRubato.GetFvKeyStreams(nonces, counter)

	heRubato.ScaleCiphertext(fvKeyStreams)

	ctBoot := heRubato.HalfBoot()

	valuesWant := make([]complex128, heRubato.params.Slots())
	for i := 0; i < heRubato.params.Slots(); i++ {
		valuesWant[i] = complex(data[0][i], 0)
	}

	fmt.Println("Precision of HalfBoot(ciphertext)")
	printDebug(heRubato.params, ctBoot, valuesWant,
		heRubato.ckksDecryptor, heRubato.ckksEncoder)
}

func printDebug(params *ckks.Parameters, ciphertext *ckks.Ciphertext,
	valuesWant []complex128, decryptor ckks.CKKSDecryptor, encoder ckks.CKKSEncoder) {

	valuesTest := encoder.DecodeComplex(decryptor.DecryptNew(ciphertext), params.LogSlots())
	logSlots := params.LogSlots()
	sigma := params.Sigma()

	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := ckks.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, logSlots, sigma)

	fmt.Println(precStats.String())
}
