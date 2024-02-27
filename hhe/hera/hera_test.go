package hera

import (
	"HHESoK/rtf_ckks_integration/ckks_fv"
	"HHESoK/sym/hera"
	"fmt"
	"math"
	"testing"
)

func testString(opName string, p hera.Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestHera(t *testing.T) {
	for _, tc := range hera.TestVector {
		// skip the test for 80-bit security
		if tc.Params.Rounds == 4 {
			continue
		}
		fmt.Println(testString("HERA", tc.Params))
		testHEHera(t, tc)
	}
}

func testHEHera(t *testing.T, tc hera.TestContext) {
	heHera := NewHEHera()
	lg := heHera.logger
	lg.PrintDataLen(tc.Key)

	var data [][]float64
	var nonces [][]byte
	var keyStream [][]uint64

	heHera.InitParams(tc.FVParamIndex, tc.Params)

	heHera.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	heHera.HalfBootKeyGen(tc.Radix)
	lg.PrintMemUsage("HalfBootKeyGen")

	heHera.InitHalfBootstrapper()
	lg.PrintMemUsage("InitHalfBootstrapper")

	heHera.InitEvaluator()
	lg.PrintMemUsage("InitEvaluator")

	heHera.InitCoefficients()
	lg.PrintMemUsage("InitCoefficients")

	if heHera.fullCoefficients {
		data = heHera.RandomDataGen(heHera.params.N())
		lg.PrintMemUsage("RandomDataGen")

		nonces = heHera.NonceGen(heHera.params.N())

		keyStream = make([][]uint64, heHera.params.N())
		symHera := hera.NewHera(tc.Key, tc.Params)
		for i := 0; i < heHera.params.N(); i++ {
			keyStream[i] = symHera.KeyStream(nonces[i])
		}
		lg.PrintMemUsage("SymKeyStreamGen")

		heHera.DataToCoefficients(data, heHera.params.N())
		lg.PrintMemUsage("DataToCoefficients")

		heHera.EncodeEncrypt(keyStream, heHera.params.N())
		lg.PrintMemUsage("EncodeEncrypt")
	} else {
		data = heHera.RandomDataGen(heHera.params.Slots())
		lg.PrintMemUsage("RandomDataGen")

		nonces = heHera.NonceGen(heHera.params.Slots())

		keyStream = make([][]uint64, heHera.params.Slots())
		symHera := hera.NewHera(tc.Key, tc.Params)
		for i := 0; i < heHera.params.Slots(); i++ {
			keyStream[i] = symHera.KeyStream(nonces[i])
		}
		lg.PrintMemUsage("SymKeyStreamGen")

		heHera.DataToCoefficients(data, heHera.params.Slots())
		lg.PrintMemUsage("DataToCoefficients")

		heHera.EncodeEncrypt(keyStream, heHera.params.Slots())
		lg.PrintMemUsage("EncodeEncrypt")
	}

	heHera.ScaleUp()
	lg.PrintMemUsage("ScaleUp")

	_ = heHera.InitFvHera()
	lg.PrintMemUsage("InitFvHera")

	// encrypts symmetric master key using BFV on the client side
	heHera.EncryptSymKey(tc.Key)
	lg.PrintMemUsage("EncryptSymKey")

	// get BFV key stream using encrypted symmetric key, nonce, and counter on the server side
	fvKeyStreams := heHera.GetFvKeyStreams(nonces)
	lg.PrintMemUsage("GetFvKeyStreams")

	heHera.ScaleCiphertext(fvKeyStreams)
	lg.PrintMemUsage("ScaleCiphertext")

	var ctBoot *ckks_fv.Ciphertext
	ctBoot = heHera.HalfBoot()
	lg.PrintMemUsage("HalfBoot")

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
