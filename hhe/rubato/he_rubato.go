package rubato

import (
	"HHESoK"
	ckks "HHESoK/ckks_integration/ckks_fv"
	"HHESoK/ckks_integration/utils"
	"HHESoK/symcips/rubato"
	"crypto/rand"
	"math"
)

type HERubato struct {
	logger          HHESoK.Logger
	paramIndex      int
	params          *ckks.Parameters
	symParams       rubato.Parameter
	hbtp            *ckks.HalfBootstrapper
	hbtpParams      *ckks.HalfBootParameters
	keyGenerator    ckks.KeyGenerator
	fvEncoder       ckks.MFVEncoder
	ckksEncoder     ckks.CKKSEncoder
	ckksDecryptor   ckks.CKKSDecryptor
	sk              *ckks.SecretKey
	pk              *ckks.PublicKey
	fvEncryptor     ckks.MFVEncryptor
	fvEvaluator     ckks.MFVEvaluator
	plainCKKSRingTs []*ckks.PlaintextRingT
	plaintexts      []*ckks.Plaintext

	fvRub          ckks.MFVRubato
	messageScaling float64
	rubatoModDown  []int
	stcModDown     []int
	pDcds          [][]*ckks.PtDiagMatrixT
	rotkeys        *ckks.RotationKeySet
	rlk            *ckks.RelinearizationKey
	hbtpKey        ckks.BootstrappingKey

	N            int
	outSize      int
	coefficients [][]float64
	symKeyCt     []*ckks.Ciphertext
	ciphertext   *ckks.Ciphertext
}

func NewHERubato() *HERubato {
	rubato := &HERubato{
		logger:          HHESoK.NewLogger(HHESoK.DEBUG),
		paramIndex:      0,
		params:          nil,
		symParams:       rubato.Parameter{},
		hbtp:            nil,
		hbtpParams:      nil,
		keyGenerator:    nil,
		fvEncoder:       nil,
		ckksEncoder:     nil,
		ckksDecryptor:   nil,
		sk:              nil,
		pk:              nil,
		fvEncryptor:     nil,
		fvEvaluator:     nil,
		plainCKKSRingTs: nil,
		plaintexts:      nil,
		fvRub:           nil,
		messageScaling:  0,
		rubatoModDown:   nil,
		stcModDown:      nil,
		pDcds:           nil,
		rotkeys:         nil,
		rlk:             nil,
		hbtpKey:         ckks.BootstrappingKey{},
		N:               0,
		outSize:         0,
		coefficients:    nil,
		symKeyCt:        nil,
		ciphertext:      nil,
	}
	return rubato
}

func (hR *HERubato) InitParams(paramIndex int, symParams rubato.Parameter, plainSize int) {
	var err error
	hR.paramIndex = paramIndex
	hR.symParams = symParams
	hR.outSize = symParams.BlockSize - 4
	hR.hbtpParams = ckks.RtFRubatoParams[0] // using Rubato 128af
	hR.params, err = hR.hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	//hR.N = int(math.Ceil(float64(plainSize / hR.outSize)))
	hR.N = hR.params.N()
	hR.params.SetPlainModulus(symParams.GetModulus())
	hR.params.SetLogFVSlots(hR.params.LogN())
	hR.messageScaling = float64(hR.params.PlainModulus()) / hR.hbtpParams.MessageRatio
	hR.rubatoModDown = ckks.RubatoModDownParams[paramIndex].CipherModDown
	hR.stcModDown = ckks.RubatoModDownParams[paramIndex].StCModDown
}

func (hR *HERubato) HEKeyGen() {
	hR.keyGenerator = ckks.NewKeyGenerator(hR.params)
	hR.sk, hR.pk = hR.keyGenerator.GenKeyPairSparse(hR.hbtpParams.H)

	hR.fvEncoder = ckks.NewMFVEncoder(hR.params)
	hR.ckksEncoder = ckks.NewCKKSEncoder(hR.params)
	hR.fvEncryptor = ckks.NewMFVEncryptorFromPk(hR.params, hR.pk)
	hR.ckksDecryptor = ckks.NewCKKSDecryptor(hR.params, hR.sk)
}

func (hR *HERubato) HalfBootKeyGen() {
	// Generating half-bootstrapping keys
	rotationsHalfBoot := hR.keyGenerator.GenRotationIndexesForHalfBoot(hR.params.LogSlots(), hR.hbtpParams)
	hR.pDcds = hR.fvEncoder.GenSlotToCoeffMatFV(2) // radix = 2
	rotationsStC := hR.keyGenerator.GenRotationIndexesForSlotsToCoeffsMat(hR.pDcds)
	rotations := append(rotationsHalfBoot, rotationsStC...)
	hR.rotkeys = hR.keyGenerator.GenRotationKeysForRotations(rotations, true, hR.sk)
	hR.rlk = hR.keyGenerator.GenRelinearizationKey(hR.sk)
	hR.hbtpKey = ckks.BootstrappingKey{Rlk: hR.rlk, Rtks: hR.rotkeys}
}

func (hR *HERubato) InitHalfBootstrapper() {
	var err error
	if hR.hbtp, err = ckks.NewHalfBootstrapper(hR.params, hR.hbtpParams, hR.hbtpKey); err != nil {
		panic(err)
	}
}

func (hR *HERubato) InitEvaluator() {
	hR.fvEvaluator = ckks.NewMFVEvaluator(hR.params, ckks.EvaluationKey{Rlk: hR.rlk, Rtks: hR.rotkeys}, hR.pDcds)
}

// InitCoefficients initialize the coefficient matrix
// coefficients = [output size * number of block]
func (hR *HERubato) InitCoefficients() {
	// Encode float data added by key stream to plaintext coefficients
	hR.coefficients = make([][]float64, hR.outSize)
	for s := 0; s < hR.outSize; s++ {
		hR.coefficients[s] = make([]float64, hR.N)
	}
}

// RandomDataGen generates the matrix of random data
// = [output size * number of block]
func (hR *HERubato) RandomDataGen() (data [][]float64) {
	data = make([][]float64, hR.outSize)
	for i := 0; i < hR.outSize; i++ {
		data[i] = make([]float64, hR.N)
		for j := 0; j < hR.N; j++ {
			data[i][j] = utils.RandFloat64(-1, 1)
		}
	}
	return
}

// NonceGen generates the matrix of nonces
//
//	= [number of block * 8]
func (hR *HERubato) NonceGen() (nonces [][]byte) {
	nonces = make([][]byte, hR.N)
	for i := 0; i < hR.N; i++ {
		nonces[i] = make([]byte, 8)
		rand.Read(nonces[i])
	}
	return
}

func (hR *HERubato) DataToCoefficients(data [][]float64) {
	for s := 0; s < hR.outSize; s++ {
		for i := 0; i < hR.N/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(hR.params.LogN()-1))
			hR.coefficients[s][j] = data[s][i]
			hR.coefficients[s][j+uint64(hR.N/2)] = data[s][i+hR.params.N()/2]
		}
	}
}

// EncodeEncrypt Encode plaintext and Encrypt with key stream
func (hR *HERubato) EncodeEncrypt(keystream [][]uint64) {
	hR.plainCKKSRingTs = make([]*ckks.PlaintextRingT, hR.outSize)
	for s := 0; s < hR.outSize; s++ {
		hR.plainCKKSRingTs[s] = hR.ckksEncoder.EncodeCoeffsRingTNew(hR.coefficients[s], hR.messageScaling)
		poly := hR.plainCKKSRingTs[s].Value()[0]
		for i := 0; i < hR.N; i++ {
			j := utils.BitReverse64(uint64(i), uint64(hR.params.LogN()))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % hR.params.PlainModulus()
		}
	}
}

func (hR *HERubato) ScaleUp() {
	hR.plaintexts = make([]*ckks.Plaintext, hR.outSize)
	for s := 0; s < hR.outSize; s++ {
		hR.plaintexts[s] = ckks.NewPlaintextFVLvl(hR.params, 0)
		hR.fvEncoder.FVScaleUp(hR.plainCKKSRingTs[s], hR.plaintexts[s])
	}
}

func (hR *HERubato) InitFvRubato() ckks.MFVRubato {
	hR.fvRub = ckks.NewMFVRubato(hR.paramIndex, hR.params, hR.fvEncoder, hR.fvEncryptor,
		hR.fvEvaluator, hR.rubatoModDown[0])
	return hR.fvRub
}

func (hR *HERubato) EncryptSymKey(key []uint64) {
	hR.symKeyCt = hR.fvRub.EncKey(key)
	hR.logger.PrintMessages(">> Symmetric Key Length: ", len(hR.symKeyCt))
}

func (hR *HERubato) GetFvKeyStreams(nonces [][]byte, counter []byte) []*ckks.Ciphertext {
	fvKeyStreams := hR.fvRub.Crypt(nonces, counter, hR.symKeyCt, hR.rubatoModDown)
	for i := 0; i < hR.outSize; i++ {
		hR.logger.PrintMessages(">> index: ", i)
		fvKeyStreams[i] = hR.fvEvaluator.SlotsToCoeffs(fvKeyStreams[i], hR.stcModDown)
		hR.fvEvaluator.ModSwitchMany(fvKeyStreams[i], fvKeyStreams[i], fvKeyStreams[i].Level())
	}
	return fvKeyStreams
}

func (hR *HERubato) ScaleCiphertext(fvKeyStreams []*ckks.Ciphertext) {
	hR.ciphertext = ckks.NewCiphertextFVLvl(hR.params, 1, 0)
	hR.ciphertext.Value()[0] = hR.plaintexts[0].Value()[0].CopyNew()
	hR.fvEvaluator.Sub(hR.ciphertext, fvKeyStreams[0], hR.ciphertext)
	hR.fvEvaluator.TransformToNTT(hR.ciphertext, hR.ciphertext)
	hR.ciphertext.SetScale(
		math.Exp2(
			math.Round(
				math.Log2(
					float64(hR.params.Qi()[0]) /
						float64(hR.params.PlainModulus()) *
						hR.messageScaling,
				),
			),
		),
	)

}

// HalfBoot Half-Bootstrap the ciphertext (homomorphic evaluation of ModRaise -> SubSum -> CtS -> EvalMod)
// It takes a ciphertext at level 0 (if not at level 0, then it will reduce it to level 0)
// and returns a ciphertext at level MaxLevel - k, where k is the depth of the bootstrapping circuit.
// Difference from the bootstrapping is that the last StC is missing.
// CAUTION: the scale of the ciphertext MUST be equal (or very close) to params.Scale
// To equalize the scale, the function evaluator.SetScale(ciphertext, parameters.Scale) can be used at the expense of one level.
func (hR *HERubato) HalfBoot() *ckks.Ciphertext {
	var ctBoot *ckks.Ciphertext
	ctBoot, _ = hR.hbtp.HalfBoot(hR.ciphertext, false)
	return ctBoot
}

// func (hR HERubato)
