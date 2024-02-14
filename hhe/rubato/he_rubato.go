package rubato

import (
	ckks "HHESoK/ckks_integration/ckks_fv"
	"HHESoK/symcips/rubato"
)

type HERubato struct {
	params          *ckks.Parameters
	symParams       rubato.Parameter
	hbtp            *ckks.HalfBootstrapper
	hbtpParams      *ckks.HalfBootParameters
	kgen            ckks.KeyGenerator
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

	outputSize int
	coeffs     [][]float64
}

func (hR HERubato) InitParams(paramIndex int) {
	var err error

	symParams := hR.symParams
	hR.outputSize = symParams.BlockSize - 4
	hR.hbtpParams = ckks.RtFRubatoParams[0]
	hR.params, err = hR.hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	hR.params.SetPlainModulus(symParams.GetModulus())
	hR.params.SetLogFVSlots(hR.params.LogN())
	hR.messageScaling = float64(hR.params.PlainModulus()) / hR.hbtpParams.MessageRatio
	hR.rubatoModDown = ckks.RubatoModDownParams[paramIndex].CipherModDown
	hR.stcModDown = ckks.RubatoModDownParams[paramIndex].StCModDown
}

func (hR HERubato) HEKeyGen() {
	hR.kgen = ckks.NewKeyGenerator(hR.params)
	hR.sk, hR.pk = hR.kgen.GenKeyPairSparse(hR.hbtpParams.H)

	hR.fvEncoder = ckks.NewMFVEncoder(hR.params)
	hR.ckksEncoder = ckks.NewCKKSEncoder(hR.params)
	hR.fvEncryptor = ckks.NewMFVEncryptorFromPk(hR.params, hR.pk)
	hR.ckksDecryptor = ckks.NewCKKSDecryptor(hR.params, hR.sk)
}

func (hR HERubato) HalfBootKeyGen() {
	// Generating half-bootstrapping keys
	rotationsHalfBoot := hR.kgen.GenRotationIndexesForHalfBoot(hR.params.LogSlots(), hR.hbtpParams)
	hR.pDcds = hR.fvEncoder.GenSlotToCoeffMatFV(2) // radix = 2
	rotationsStC := hR.kgen.GenRotationIndexesForSlotsToCoeffsMat(hR.pDcds)
	rotations := append(rotationsHalfBoot, rotationsStC...)
	hR.rotkeys = hR.kgen.GenRotationKeysForRotations(rotations, true, hR.sk)
	hR.rlk = hR.kgen.GenRelinearizationKey(hR.sk)
	hR.hbtpKey = ckks.BootstrappingKey{Rlk: hR.rlk, Rtks: hR.rotkeys}
}

func (hR HERubato) InitHalfBootstrapper() {
	var err error
	if hR.hbtp, err = ckks.NewHalfBootstrapper(hR.params, hR.hbtpParams, hR.hbtpKey); err != nil {
		panic(err)
	}
}

func (hR HERubato) InitEvaluator() {
	hR.fvEvaluator = ckks.NewMFVEvaluator(hR.params, ckks.EvaluationKey{Rlk: hR.rlk, Rtks: hR.rotkeys}, hR.pDcds)
}

func (hR HERubato) InitCoefficients() {
	// Encode float data added by key stream to plaintext coefficients
	coeffs := make([][]float64, hR.outputSize)
	for s := 0; s < hR.outputSize; s++ {
		coeffs[s] = make([]float64, hR.params.N())
	}
}

// func (hR HERubato)
