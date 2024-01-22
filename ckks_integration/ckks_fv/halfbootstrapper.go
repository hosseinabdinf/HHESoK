package ckks_fv

import (
	"fmt"
	"math"

	"HHESoK/ckks_integration/ckks/bettersine"
	"HHESoK/ckks_integration/utils"
)

// HalfBootstrapper is a struct to stores a memory pool the plaintext matrices
// the polynomial approximation and the keys for the half-bootstrapping.
type HalfBootstrapper struct {
	*ckksEvaluator
	HalfBootParameters
	*BootstrappingKey
	params *Parameters

	dslots    int // Number of plaintext slots after the re-encoding
	logdslots int

	encoder CKKSEncoder // Encoder

	prescale     float64                 // Q[0]/(Q[0]/|m|)
	postscale    float64                 // Qi sineeval/(Q[0]/|m|)
	sinescale    float64                 // Qi sineeval
	sqrt2pi      float64                 // (1/2pi)^{-2^r}
	scFac        float64                 // 2^{r}
	sineEvalPoly *ChebyshevInterpolation // Coefficients of the Chebyshev Interpolation of sin(2*pi*x) or cos(2*pi*x/r)
	arcSinePoly  *Poly                   // Coefficients of the Taylor series of arcsine(x)

	coeffsToSlotsDiffScale complex128      // Matrice rescaling
	diffScaleAfterSineEval float64         // Matrice rescaling
	pDFTInvWithoutRepack   []*PtDiagMatrix // Matrice vectors

	rotKeyIndex []int // a list of the required rotation keys
}

// NewHalfBootstrapper creates a new HalfBootstrapper.
func NewHalfBootstrapper(params *Parameters, hbtpParams *HalfBootParameters, btpKey BootstrappingKey) (hbtp *HalfBootstrapper, err error) {

	if hbtpParams.SinType == SinType(Sin) && hbtpParams.SinRescal != 0 {
		return nil, fmt.Errorf("cannot use double angle formul for SinType = Sin -> must use SinType = Cos")
	}

	hbtp = newHalfBootstrapper(params, hbtpParams)

	hbtp.BootstrappingKey = &BootstrappingKey{btpKey.Rlk, btpKey.Rtks}
	if err = hbtp.CheckKeys(); err != nil {
		return nil, fmt.Errorf("invalid bootstrapping key: %w", err)
	}
	hbtp.ckksEvaluator = hbtp.ckksEvaluator.WithKey(EvaluationKey{btpKey.Rlk, btpKey.Rtks}).(*ckksEvaluator)

	return hbtp, nil
}

// newHalfBootstrapper is a constructor of "dummy" half-bootstrapper to enable the generation of bootstrapping-related constants
// without providing a bootstrapping key. To be replaced by a propper factorization of the bootstrapping pre-computations.
func newHalfBootstrapper(params *Parameters, hbtpParams *HalfBootParameters) (hbtp *HalfBootstrapper) {
	hbtp = new(HalfBootstrapper)

	hbtp.params = params.Copy()
	hbtp.HalfBootParameters = *hbtpParams.Copy()

	hbtp.dslots = params.Slots()
	hbtp.logdslots = params.LogSlots()
	if params.logSlots < params.MaxLogSlots() {
		hbtp.dslots <<= 1
		hbtp.logdslots++
	}

	hbtp.prescale = math.Exp2(math.Round(math.Log2(float64(params.qi[0]) / hbtp.MessageRatio)))
	hbtp.sinescale = math.Exp2(math.Round(math.Log2(hbtp.SineEvalModuli.ScalingFactor)))
	hbtp.postscale = hbtp.sinescale / hbtp.MessageRatio

	hbtp.encoder = NewCKKSEncoder(params)
	hbtp.ckksEvaluator = NewCKKSEvaluator(params, EvaluationKey{}).(*ckksEvaluator) // creates an evaluator without keys for genDFTMatrices

	hbtp.genSinePoly()
	hbtp.genDFTMatrices()

	hbtp.ctxpool = NewCiphertextCKKS(params, 1, params.MaxLevel(), 0)

	return hbtp
}

// CheckKeys checks if all the necessary keys are present
func (hbtp *HalfBootstrapper) CheckKeys() (err error) {

	if hbtp.Rlk == nil {
		return fmt.Errorf("relinearization key is nil")
	}

	if hbtp.Rtks == nil {
		return fmt.Errorf("rotation key is nil")
	}

	rotMissing := []int{}
	for _, i := range hbtp.rotKeyIndex {
		galEl := hbtp.params.GaloisElementForColumnRotationBy(int(i))
		if _, generated := hbtp.Rtks.Keys[galEl]; !generated {
			rotMissing = append(rotMissing, i)
		}
	}

	if len(rotMissing) != 0 {
		return fmt.Errorf("rotation key(s) missing: %d", rotMissing)
	}

	return nil
}

func (hbtp *HalfBootstrapper) genDFTMatrices() {

	a := real(hbtp.sineEvalPoly.a)
	b := real(hbtp.sineEvalPoly.b)
	n := float64(hbtp.params.N())
	qDiff := float64(hbtp.params.qi[0]) / math.Exp2(math.Round(math.Log2(float64(hbtp.params.qi[0]))))

	// Change of variable for the evaluation of the Chebyshev polynomial + cancelling factor for the DFT and SubSum + evantual scaling factor for the double angle formula
	hbtp.coeffsToSlotsDiffScale = complex(math.Pow(2.0/((b-a)*n*hbtp.scFac*qDiff), 1.0/float64(hbtp.CtSDepth(false))), 0)

	// Rescaling factor to set the final ciphertext to the desired scale
	hbtp.diffScaleAfterSineEval = (qDiff * hbtp.params.scale) / hbtp.postscale

	// CoeffsToSlotsWithoutRepack vectors
	hbtp.pDFTInvWithoutRepack = hbtp.HalfBootParameters.GenCoeffsToSlotsMatrixWithoutRepack(hbtp.coeffsToSlotsDiffScale, hbtp.encoder)

	// List of the rotation key values to needed for the bootstrapp
	hbtp.rotKeyIndex = []int{}

	//SubSum rotation needed X -> Y^slots rotations
	for i := hbtp.params.logSlots; i < hbtp.params.MaxLogSlots(); i++ {
		if !utils.IsInSliceInt(1<<i, hbtp.rotKeyIndex) {
			hbtp.rotKeyIndex = append(hbtp.rotKeyIndex, 1<<i)
		}
	}

	// Coeffs to Slots rotations
	for _, pVec := range hbtp.pDFTInvWithoutRepack {
		hbtp.rotKeyIndex = AddMatrixRotToList(pVec, hbtp.rotKeyIndex, hbtp.params.Slots(), false)
	}
}

func (hbtp *HalfBootstrapper) genSinePoly() {

	K := int(hbtp.SinRange)
	deg := int(hbtp.SinDeg)
	hbtp.scFac = float64(int(1 << hbtp.SinRescal))

	if hbtp.ArcSineDeg > 0 {
		hbtp.sqrt2pi = 1.0

		coeffs := make([]complex128, hbtp.ArcSineDeg+1)

		coeffs[1] = 0.15915494309189535

		for i := 3; i < hbtp.ArcSineDeg+1; i += 2 {

			coeffs[i] = coeffs[i-2] * complex(float64(i*i-4*i+4)/float64(i*i-i), 0)

		}

		hbtp.arcSinePoly = NewPoly(coeffs)

	} else {
		hbtp.sqrt2pi = math.Pow(0.15915494309189535, 1.0/hbtp.scFac)
	}

	if hbtp.SinType == Sin {

		hbtp.sineEvalPoly = Approximate(sin2pi2pi, -complex(float64(K)/hbtp.scFac, 0), complex(float64(K)/hbtp.scFac, 0), deg)

	} else if hbtp.SinType == Cos1 {

		hbtp.sineEvalPoly = new(ChebyshevInterpolation)

		hbtp.sineEvalPoly.coeffs = bettersine.Approximate(K, deg, hbtp.MessageRatio, int(hbtp.SinRescal))

		hbtp.sineEvalPoly.maxDeg = hbtp.sineEvalPoly.Degree()
		hbtp.sineEvalPoly.a = complex(float64(-K)/hbtp.scFac, 0)
		hbtp.sineEvalPoly.b = complex(float64(K)/hbtp.scFac, 0)
		hbtp.sineEvalPoly.lead = true

	} else if hbtp.SinType == Cos2 {

		hbtp.sineEvalPoly = Approximate(cos2pi, -complex(float64(K)/hbtp.scFac, 0), complex(float64(K)/hbtp.scFac, 0), deg)

	} else {
		panic("Bootstrapper -> invalid sineType")
	}

	for i := range hbtp.sineEvalPoly.coeffs {
		hbtp.sineEvalPoly.coeffs[i] *= complex(hbtp.sqrt2pi, 0)
	}
}
