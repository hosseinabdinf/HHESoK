package ckks_fv

import (
	"math"
	//"fmt"
)

// HalfBootParameters is a struct for the default half-boot parameters
type HalfBootParameters struct {
	ResidualModuli
	KeySwitchModuli
	SineEvalModuli
	DiffScaleModulus
	CoeffsToSlotsModuli
	LogN         int
	LogSlots     int
	PlainModulus uint64
	Scale        float64
	Sigma        float64
	H            int     // Hamming weight of the secret key
	SinType      SinType // Chose betwenn [Sin(2*pi*x)] or [cos(2*pi*x/r) with double angle formula]
	MessageRatio float64 // Ratio between Q0 and m, i.e. Q[0]/|m|
	SinRange     int     // K parameter (interpolation in the range -K to K)
	SinDeg       int     // Degree of the interpolation
	SinRescal    int     // Number of rescale and double angle formula (only applies for cos)
	ArcSineDeg   int     // Degree of the Taylor arcsine composed with f(2*pi*x) (if zero then not used)
	MaxN1N2Ratio float64 // n1/n2 ratio for the bsgs algo for matrix x vector eval
}

// Params generates a new set of Parameters from the HalfBootParameters
func (hb *HalfBootParameters) Params() (p *Parameters, err error) {
	Qi := append(hb.ResidualModuli, hb.DiffScaleModulus...)
	Qi = append(Qi, hb.SineEvalModuli.Qi...)
	Qi = append(Qi, hb.CoeffsToSlotsModuli.Qi...)

	if p, err = NewParametersFromModuli(hb.LogN, &Moduli{Qi, hb.KeySwitchModuli}, hb.PlainModulus); err != nil {
		return nil, err
	}

	p.SetScale(hb.Scale)
	p.SetLogSlots(hb.LogSlots)
	p.SetSigma(hb.Sigma)
	return
}

// Copy return a new HalfBootParameters which is a copy of the target
func (hb *HalfBootParameters) Copy() *HalfBootParameters {
	paramsCopy := &HalfBootParameters{
		LogN:         hb.LogN,
		LogSlots:     hb.LogSlots,
		PlainModulus: hb.PlainModulus,
		Scale:        hb.Scale,
		Sigma:        hb.Sigma,
		H:            hb.H,
		SinType:      hb.SinType,
		MessageRatio: hb.MessageRatio,
		SinRange:     hb.SinRange,
		SinDeg:       hb.SinDeg,
		SinRescal:    hb.SinRescal,
		ArcSineDeg:   hb.ArcSineDeg,
		MaxN1N2Ratio: hb.MaxN1N2Ratio,
	}

	// KeySwitchModuli
	paramsCopy.KeySwitchModuli = make([]uint64, len(hb.KeySwitchModuli))
	copy(paramsCopy.KeySwitchModuli, hb.KeySwitchModuli)

	// ResidualModuli
	paramsCopy.ResidualModuli = make([]uint64, len(hb.ResidualModuli))
	copy(paramsCopy.ResidualModuli, hb.ResidualModuli)

	// CoeffsToSlotsModuli
	paramsCopy.CoeffsToSlotsModuli.Qi = make([]uint64, hb.CtSDepth(true))
	copy(paramsCopy.CoeffsToSlotsModuli.Qi, hb.CoeffsToSlotsModuli.Qi)

	paramsCopy.CoeffsToSlotsModuli.ScalingFactor = make([][]float64, hb.CtSDepth(true))
	for i := range paramsCopy.CoeffsToSlotsModuli.ScalingFactor {
		paramsCopy.CoeffsToSlotsModuli.ScalingFactor[i] = make([]float64, len(hb.CoeffsToSlotsModuli.ScalingFactor[i]))
		copy(paramsCopy.CoeffsToSlotsModuli.ScalingFactor[i], hb.CoeffsToSlotsModuli.ScalingFactor[i])
	}

	// SineEvalModuli
	paramsCopy.SineEvalModuli.Qi = make([]uint64, len(hb.SineEvalModuli.Qi))
	copy(paramsCopy.SineEvalModuli.Qi, hb.SineEvalModuli.Qi)
	paramsCopy.SineEvalModuli.ScalingFactor = hb.SineEvalModuli.ScalingFactor

	// DiffScaelModulus
	paramsCopy.DiffScaleModulus = make([]uint64, 1)
	copy(paramsCopy.DiffScaleModulus, hb.DiffScaleModulus)

	return paramsCopy
}

// DiffScaleModulus is used to set scale after the SineEval step.
type DiffScaleModulus []uint64

// MaxLevel returns the maximum level of the halfboot parameters
func (hb *HalfBootParameters) MaxLevel() int {
	return len(hb.ResidualModuli) + len(hb.DiffScaleModulus) + len(hb.CoeffsToSlotsModuli.Qi) + len(hb.SineEvalModuli.Qi) - 1
}

// SineEvalDepth returns the depth of the SineEval. If true, then also
// counts the double angle formula.
func (hb *HalfBootParameters) SineEvalDepth(withRescale bool) int {
	depth := int(math.Ceil(math.Log2(float64(hb.SinDeg + 1))))

	if withRescale {
		depth += hb.SinRescal
	}

	return depth
}

// ArcSineDepth returns the depth of the arcsine polynomial.
func (hb *HalfBootParameters) ArcSineDepth() int {
	return int(math.Ceil(math.Log2(float64(hb.ArcSineDeg + 1))))
}

// CtSDepth returns the number of levels allocated to CoeffsToSlots.
// If actual == true then returns the number of moduli consumed, else
// returns the factorization depth.
func (hb *HalfBootParameters) CtSDepth(actual bool) (depth int) {
	if actual {
		depth = len(hb.CoeffsToSlotsModuli.ScalingFactor)
	} else {
		for i := range hb.CoeffsToSlotsModuli.ScalingFactor {
			for range hb.CoeffsToSlotsModuli.ScalingFactor[i] {
				depth++
			}
		}
	}

	return
}

// CtSLevels returns the index of the Qi used int CoeffsToSlots
func (hb *HalfBootParameters) CtSLevels() (ctsLevel []int) {
	ctsLevel = []int{}
	for i := range hb.CoeffsToSlotsModuli.Qi {
		for range hb.CoeffsToSlotsModuli.ScalingFactor[hb.CtSDepth(true)-1-i] {
			ctsLevel = append(ctsLevel, hb.MaxLevel()-i)
		}
	}

	return
}

// GenCoeffsToSlotsMatrixWithoutRepack generates the factorized encoding matrix
// scaling : constant by witch the all the matrices will be multiplied by
// encoder : ckks.Encoder
func (hb *HalfBootParameters) GenCoeffsToSlotsMatrixWithoutRepack(scaling complex128, encoder CKKSEncoder) []*PtDiagMatrix {

	logSlots := hb.LogSlots
	slots := 1 << logSlots
	depth := hb.CtSDepth(false)
	logdSlots := logSlots + 1
	if logdSlots == hb.LogN {
		logdSlots--
	}

	roots := computeRoots(slots << 1)
	pow5 := make([]int, (slots<<1)+1)
	pow5[0] = 1
	for i := 1; i < (slots<<1)+1; i++ {
		pow5[i] = pow5[i-1] * 5
		pow5[i] &= (slots << 2) - 1
	}

	ctsLevels := hb.CtSLevels()

	// CoeffsToSlots vectors
	pDFTInv := make([]*PtDiagMatrix, len(ctsLevels))
	pVecDFTInv := computeDFTMatricesWithoutRepack(logSlots, logdSlots, depth, roots, pow5, scaling, true)
	cnt := 0
	for i := range hb.CoeffsToSlotsModuli.ScalingFactor {
		for j := range hb.CoeffsToSlotsModuli.ScalingFactor[hb.CtSDepth(true)-i-1] {
			pDFTInv[cnt] = encoder.EncodeDiagMatrixAtLvl(ctsLevels[cnt], pVecDFTInv[cnt], hb.CoeffsToSlotsModuli.ScalingFactor[hb.CtSDepth(true)-i-1][j], hb.MaxN1N2Ratio, logdSlots)
			cnt++
		}
	}

	return pDFTInv
}

func computeDFTMatricesWithoutRepack(logSlots, logdSlots, maxDepth int, roots []complex128, pow5 []int, diffscale complex128, inverse bool) (plainVector []map[int][]complex128) {

	bitreversed := false

	var fftLevel, depth, nextfftLevel int

	fftLevel = logSlots

	var a, b, c [][]complex128

	if inverse {
		a, b, c = fftInvPlainVec(logSlots, 1<<logdSlots, roots, pow5)
	} else {
		a, b, c = fftPlainVec(logSlots, 1<<logdSlots, roots, pow5)
	}

	plainVector = make([]map[int][]complex128, maxDepth)

	// We compute the chain of merge in order or reverse order depending if its DFT or InvDFT because
	// the way the levels are collapsed has an inpact on the total number of rotations and keys to be
	// stored. Ex. instead of using 255 + 64 plaintext vectors, we can use 127 + 128 plaintext vectors
	// by reversing the order of the merging.
	merge := make([]int, maxDepth)
	for i := 0; i < maxDepth; i++ {

		depth = int(math.Ceil(float64(fftLevel) / float64(maxDepth-i)))

		if inverse {
			merge[i] = depth
		} else {
			merge[len(merge)-i-1] = depth

		}

		fftLevel -= depth
	}

	fftLevel = logSlots
	for i := 0; i < maxDepth; i++ {
		// First layer of the i-th level of the DFT
		plainVector[i] = genFFTDiagMatrix(logSlots, fftLevel, a[logSlots-fftLevel], b[logSlots-fftLevel], c[logSlots-fftLevel], inverse, bitreversed)

		// Merges the layer with the next levels of the DFT if the total depth requires it.
		nextfftLevel = fftLevel - 1
		for j := 0; j < merge[i]-1; j++ {
			plainVector[i] = multiplyFFTMatrixWithNextFFTLevel(plainVector[i], logSlots, 1<<logSlots, nextfftLevel, a[logSlots-nextfftLevel], b[logSlots-nextfftLevel], c[logSlots-nextfftLevel], inverse, bitreversed)
			nextfftLevel--
		}

		fftLevel -= merge[i]
	}

	// Rescaling of the DFT matrix of the SlotsToCoeffs/CoeffsToSlots
	for j := range plainVector {
		for x := range plainVector[j] {
			for i := range plainVector[j][x] {
				plainVector[j][x][i] *= diffscale
			}
		}
	}

	return
}

func (hb *HalfBootParameters) SetLogSlots(logslot int) {
	hb.LogSlots = logslot
}
