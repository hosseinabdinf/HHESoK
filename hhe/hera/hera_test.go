package hera

import (
	"HHESoK"
	"HHESoK/rtf_ckks_integration/ckks_fv"
	"HHESoK/symcips/hera"
	"fmt"
	"math"
	"testing"
)

func testString(opName string, p hera.Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestHera(t *testing.T) {
	logger := HHESoK.NewLogger(HHESoK.DEBUG)
	for _, tc := range hera.TestVector {
		// skip the test for 80-bit security
		if tc.Params.Rounds == 4 {
			continue
		}
		fmt.Println(testString("HERA", tc.Params))
		logger.PrintDataLen(tc.Key)
		testHEHera(t, tc)
	}
}

func testHEHera(t *testing.T, tc hera.TestContext) {
	heHera := NewHEHera()

	var data [][]float64
	var nonces [][]byte
	var keyStream [][]uint64

	heHera.InitParams(tc.FVParamIndex, tc.Params)

	heHera.HEKeyGen()

	heHera.HalfBootKeyGen(tc.Radix)

	heHera.InitHalfBootstrapper()

	heHera.InitEvaluator()

	heHera.InitCoefficients()

	if heHera.fullCoefficients {
		data = heHera.RandomDataGen(heHera.params.N())

		nonces = heHera.NonceGen(heHera.params.N())

		keyStream = make([][]uint64, heHera.params.N())
		for i := 0; i < heHera.params.N(); i++ {
			symHera := hera.NewHera(tc.Key, tc.Params)
			keyStream[i] = symHera.KeyStream(nonces[i])
		}

		heHera.DataToCoefficients(data, heHera.params.N())

		heHera.EncodeEncrypt(keyStream, heHera.params.N())

	} else {
		data = heHera.RandomDataGen(heHera.params.Slots())

		nonces = heHera.NonceGen(heHera.params.Slots())

		keyStream = make([][]uint64, heHera.params.Slots())
		for i := 0; i < heHera.params.Slots(); i++ {
			symHera := hera.NewHera(tc.Key, tc.Params)
			keyStream[i] = symHera.KeyStream(nonces[i])
		}

		heHera.DataToCoefficients(data, heHera.params.Slots())

		heHera.EncodeEncrypt(keyStream, heHera.params.Slots())
	}

	heHera.ScaleUp()

	// FV Key Stream, encrypts symmetric key stream using BFV on the client side
	_ = heHera.InitFvHera()
	heHera.EncryptSymKey(tc.Key)

	// get BFV key stream using encrypted symmetric key, nonce, and counter on the server side
	fvKeyStreams := heHera.GetFvKeyStreams(nonces)

	heHera.ScaleCiphertext(fvKeyStreams)

	var ctBoot *ckks_fv.Ciphertext
	ctBoot = heHera.HalfBoot()

	valuesWant := make([]complex128, heHera.params.Slots())
	for i := 0; i < heHera.params.Slots(); i++ {
		valuesWant[i] = complex(data[0][i], 0)
	}

	fmt.Println("Precision of HalfBoot(ciphertext)")
	printDebug(heHera.params, ctBoot, valuesWant,
		heHera.ckksDecryptor, heHera.ckksEncoder)
}

func printDebug(params *ckks_fv.Parameters, ciphertext *ckks_fv.Ciphertext, valuesWant []complex128, decryptor ckks_fv.CKKSDecryptor, encoder ckks_fv.CKKSEncoder) {
	valuesTest := encoder.DecodeComplex(decryptor.DecryptNew(ciphertext), params.LogSlots())
	logSlots := params.LogSlots()
	sigma := params.Sigma()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
	precisionState := ckks_fv.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, logSlots, sigma)
	fmt.Println(precisionState.String())
}
