package rubato

import (
	"HHESoK"
	ckks "HHESoK/ckks_integration/ckks_fv"
	"HHESoK/ckks_integration/utils"
	"HHESoK/symcips/rubato"
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
		rubatoCipher := rubato.NewRubato(tc.Key, tc.Params)
		encryptor := rubatoCipher.NewEncryptor()
		var ciphertext HHESoK.Ciphertext

		t.Run("RubatoEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.Plaintext)
		})

		t.Run("RubatoDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		logger.PrintDataLen(tc.Key)
		logger.PrintDataLen(ciphertext)
	}
}

func benchmarkRtFRubato(b *testing.B, rubatoParam int) {
	var err error

	var heRubato HERubato
	heRubato.InitParams(ckks.RUBATO128S)

	heRubato.HEKeyGen()

	heRubato.HalfBootKeyGen()

	heRubato.InitHalfBootstrapper()

	heRubato.InitEvaluator()

	heRubato.InitCoefficients()

	// Rubato parameter
	blocksize := ckks.RubatoParams[rubatoParam].Blocksize
	numRound := ckks.RubatoParams[rubatoParam].NumRound
	plainModulus := ckks.RubatoParams[rubatoParam].PlainModulus
	sigma := ckks.RubatoParams[rubatoParam].Sigma

	// todo: use the key from test vector
	// Key generation
	//key = make([]uint64, blocksize)
	//for i := 0; i < blocksize; i++ {
	//	key[i] = uint64(i + 1) // Use (1, ..., 16) for testing
	//}

	// todo: use the plaintext data from test vector
	// Get random data in [-1, 1]
	//data = make([][]float64, outputsize)
	//for s := 0; s < outputsize; s++ {
	//	data[s] = make([]float64, params.N())
	//	for i := 0; i < params.N(); i++ {
	//		data[s][i] = utils.RandFloat64(-1, 1)
	//	}
	//}

	// todo: need an array of 8-byte nonces for each data
	//nonces = make([][]byte, params.N())
	//for i := 0; i < params.N(); i++ {
	//	nonces[i] = make([]byte, 8)
	//	rand.Read(nonces[i])
	//}
	//todo: need a 8-byte counter
	//counter = make([]byte, 8)
	//rand.Read(counter)

	// todo: generate keystream using plain rubato
	// Get keystream
	//keystream = make([][]uint64, params.N())
	//for i := 0; i < params.N(); i++ {
	//	keystream[i] = plainRubato(blocksize, numRound, nonces[i], counter, key, plainModulus, sigma)
	//}

	// data to coefficients
	for s := 0; s < outputsize; s++ {
		for i := 0; i < params.N()/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
			coeffs[s][j] = data[s][i]
			coeffs[s][j+uint64(params.N()/2)] = data[s][i+params.N()/2]
		}
	}

	// Encode plaintext and Encrypt with key stream
	plainCKKSRingTs = make([]*ckks.PlaintextRingT, outputsize)
	for s := 0; s < outputsize; s++ {
		plainCKKSRingTs[s] = ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], messageScaling)
		poly := plainCKKSRingTs[s].Value()[0]
		for i := 0; i < params.N(); i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % params.PlainModulus()
		}
	}

	plaintexts = make([]*ckks.Plaintext, outputsize)
	for s := 0; s < outputsize; s++ {
		plaintexts[s] = ckks.NewPlaintextFVLvl(params, 0)
		fvEncoder.FVScaleUp(plainCKKSRingTs[s], plaintexts[s])
	}

	// FV Keystream
	rub = ckks.NewMFVRubato(rubatoParam, params, fvEncoder, fvEncryptor, fvEvaluator, rubatoModDown[0])
	kCt := rub.EncKey(key)

	benchOffLat := fmt.Sprintf("RtF Rubato Offline Latency")
	b.Run(benchOffLat, func(b *testing.B) {
		fvKeystreams = rub.Crypt(nonces, counter, kCt, rubatoModDown)
		for i := 0; i < 1; i++ {
			fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i], stcModDown)
			fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
		}
	})
	/* We assume that b.N == 1 */
	benchOffThrput := fmt.Sprintf("RtF Rubato Offline Throughput")
	b.Run(benchOffThrput, func(b *testing.B) {
		for i := 1; i < outputsize; i++ {
			fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i], stcModDown)
			fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
		}
	})

	var ctBoot *ckks.Ciphertext
	benchOnline := fmt.Sprintf("RtF Rubato Online Lat x1")
	b.Run(benchOnline, func(b *testing.B) {
		// Encrypt and mod switch to the lowest level
		ciphertext := ckks.NewCiphertextFVLvl(params, 1, 0)
		ciphertext.Value()[0] = plaintexts[0].Value()[0].CopyNew()
		fvEvaluator.Sub(ciphertext, fvKeystreams[0], ciphertext)
		fvEvaluator.TransformToNTT(ciphertext, ciphertext)
		ciphertext.SetScale(math.Exp2(math.Round(math.Log2(float64(params.Qi()[0]) / float64(params.PlainModulus()) * messageScaling))))

		// Half-Bootstrap the ciphertext (homomorphic evaluation of ModRaise -> SubSum -> CtS -> EvalMod)
		// It takes a ciphertext at level 0 (if not at level 0, then it will reduce it to level 0)
		// and returns a ciphertext at level MaxLevel - k, where k is the depth of the bootstrapping circuit.
		// Difference from the bootstrapping is that the last StC is missing.
		// CAUTION: the scale of the ciphertext MUST be equal (or very close) to params.Scale
		// To equalize the scale, the function evaluator.SetScale(ciphertext, parameters.Scale) can be used at the expense of one level.
		ctBoot, _ = hbtp.HalfBoot(ciphertext, false)
	})
	valuesWant := make([]complex128, params.Slots())
	for i := 0; i < params.Slots(); i++ {
		valuesWant[i] = complex(data[0][i], 0)
	}

	fmt.Println("Precision of HalfBoot(ciphertext)")
	printDebug(params, ctBoot, valuesWant, ckksDecryptor, ckksEncoder)
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
