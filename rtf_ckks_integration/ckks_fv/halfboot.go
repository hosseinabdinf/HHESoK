package ckks_fv

import (
	"math"

	"HHESoK/rtf_ckks_integration/ring"
)

// Halfboot follows bootstrapping process except the last StC step.
// If the input ciphertext level is zero, the input scale must be an exact power of two smaller or equal to round(Q0/2^{10}).
// If the input ciphertext is at level one or more, the input scale does not need to be an exact power of two as one level
// can be used to do a scale matching.
func (hbtp *HalfBootstrapper) HalfBoot(ct *Ciphertext, repack bool) (ct0, ct1 *Ciphertext) {

	//var t time.Time
	// var ct0, ct1 *Ciphertext

	// Drops the level to 1
	for ct.Level() > 1 {
		hbtp.ckksEvaluator.DropLevel(ct, 1)
	}

	// Brings the ciphertext scale to Q0/2^{10}
	if ct.Level() == 1 {

		// if one level is available, then uses it to match the scale
		hbtp.ckksEvaluator.SetScale(ct, hbtp.prescale)

		// then drops to level 0
		for ct.Level() != 0 {
			hbtp.ckksEvaluator.DropLevel(ct, 1)
		}

	} else {

		// else drop to level 0
		for ct.Level() != 0 {
			hbtp.ckksEvaluator.DropLevel(ct, 1)
		}

		// and does an integer constant mult by round((Q0/Delta_m)/ctscle)

		if hbtp.prescale < ct.Scale() {
			panic("ciphetext scale > Q[0]/(Q[0]/Delta_m)")
		}
		hbtp.ckksEvaluator.ScaleUp(ct, math.Round(hbtp.prescale/ct.Scale()), ct)
	}

	// ModUp ct_{Q_0} -> ct_{Q_L}
	//t = time.Now()
	ct = hbtp.modUp(ct)
	//log.Println("After ModUp  :", time.Now().Sub(t), ct.Level(), ct.Scale())

	// Brings the ciphertext scale to sineQi/(Q0/scale) if its under
	hbtp.ckksEvaluator.ScaleUp(ct, math.Round(hbtp.postscale/ct.Scale()), ct)

	//SubSum X -> (N/dslots) * Y^dslots
	//t = time.Now()
	ct = hbtp.subSum(ct)
	//log.Println("After SubSum :", time.Now().Sub(t), ct.Level(), ct.Scale())
	// Part 1 : Coeffs to slots

	//t = time.Now()
	// ct0, ct1 = CoeffsToSlots(ct, hbtp.pDFTInv, hbtp.ckksEvaluator)
	ct0, ct1 = CoeffsToSlotsWithoutRepack(ct, hbtp.pDFTInvWithoutRepack, hbtp.ckksEvaluator)
	//log.Println("After CtS    :", time.Now().Sub(t), ct0.Level(), ct0.Scale())

	// Part 2 : SineEval
	//t = time.Now()
	if repack {
		hbtp.ckksEvaluator.Rotate(ct1, hbtp.params.Slots()/2, ct1)
		hbtp.ckksEvaluator.Add(ct0, ct1, ct0)
		ct0, _ = hbtp.evaluateSine(ct0, nil)
		ct1 = nil
	} else {
		ct0, ct1 = hbtp.evaluateSine(ct0, ct1)
	}
	//log.Println("After Sine   :", time.Now().Sub(t), ct0.Level(), ct0.Scale())

	// Part 3 : Fix scale using diffScaleAfterEvalSine
	hbtp.ckksEvaluator.MultByConst(ct0, hbtp.diffScaleAfterSineEval, ct0)
	if err := hbtp.ckksEvaluator.RescaleMany(ct0, 1, ct0); err != nil {
		panic(err)
	}
	// Rounds to the nearest power of two
	ct0.SetScale(math.Exp2(math.Round(math.Log2(ct0.Scale()))))

	if ct1 != nil {
		hbtp.ckksEvaluator.MultByConst(ct1, hbtp.diffScaleAfterSineEval, ct1)
		if err := hbtp.ckksEvaluator.RescaleMany(ct1, 1, ct1); err != nil {
			panic(err)
		}
		// Rounds to the nearest power of two
		ct1.SetScale(math.Exp2(math.Round(math.Log2(ct1.Scale()))))
	}

	return ct0, ct1
}

func (hbtp *HalfBootstrapper) subSum(ct *Ciphertext) *Ciphertext {

	for i := hbtp.params.logSlots; i < hbtp.params.MaxLogSlots(); i++ {

		hbtp.ckksEvaluator.Rotate(ct, 1<<i, hbtp.ckksEvaluator.ctxpool)

		hbtp.ckksEvaluator.Add(ct, hbtp.ckksEvaluator.ctxpool, ct)
	}

	return ct
}

func (hbtp *HalfBootstrapper) modUp(ct *Ciphertext) *Ciphertext {

	ringQ := hbtp.ckksEvaluator.ringQ

	ct.InvNTT(ringQ, ct.El())

	// Extend the ciphertext with zero polynomials.
	for u := range ct.Value() {
		ct.Value()[u].Coeffs = append(ct.Value()[u].Coeffs, make([][]uint64, hbtp.params.MaxLevel())...)
		for i := 1; i < hbtp.params.MaxLevel()+1; i++ {
			ct.Value()[u].Coeffs[i] = make([]uint64, hbtp.params.N())
		}
	}

	//Centers the values around Q0 and extends the basis from Q0 to QL
	Q := ringQ.Modulus[0]
	bredparams := ringQ.BredParams

	var coeff, qi uint64
	for u := range ct.Value() {

		for j := 0; j < hbtp.params.N(); j++ {

			coeff = ct.Value()[u].Coeffs[0][j]

			for i := 1; i < hbtp.params.MaxLevel()+1; i++ {

				qi = ringQ.Modulus[i]

				if coeff > (Q >> 1) {
					ct.Value()[u].Coeffs[i][j] = qi - ring.BRedAdd(Q-coeff, qi, bredparams[i])
				} else {
					ct.Value()[u].Coeffs[i][j] = ring.BRedAdd(coeff, qi, bredparams[i])
				}
			}
		}
	}

	ct.NTT(ringQ, ct.El())

	return ct
}

func CoeffsToSlotsWithoutRepack(vec *Ciphertext, pDFTInv []*PtDiagMatrix, eval CKKSEvaluator) (ct0, ct1 *Ciphertext) {

	var zV, zVconj *Ciphertext

	zV = dft(vec, pDFTInv, true, eval)

	zVconj = eval.ConjugateNew(zV)

	// The real part is stored in ct0
	ct0 = eval.AddNew(zV, zVconj)

	// The imaginary part is stored in ct1
	ct1 = eval.SubNew(zV, zVconj)

	eval.DivByi(ct1, ct1)

	zV = nil
	zVconj = nil

	return ct0, ct1
}

// Sine Evaluation ct0 = Q/(2pi) * sin((2pi/Q) * ct0)
func (hbtp *HalfBootstrapper) evaluateSine(ct0, ct1 *Ciphertext) (*Ciphertext, *Ciphertext) {

	ct0.MulScale(hbtp.MessageRatio)
	hbtp.ckksEvaluator.scale = hbtp.sinescale // Reference scale is changed to the Qi used for the SineEval (which is also close to the new ciphetext scale)

	ct0 = hbtp.evaluateCheby(ct0)

	ct0.DivScale(hbtp.MessageRatio * hbtp.postscale / hbtp.params.scale)

	if ct1 != nil {
		ct1.MulScale(hbtp.MessageRatio)
		ct1 = hbtp.evaluateCheby(ct1)
		ct1.DivScale(hbtp.MessageRatio * hbtp.postscale / hbtp.params.scale)
	}

	// Reference scale is changed back to the current ciphertext's scale.
	hbtp.ckksEvaluator.scale = ct0.Scale()

	return ct0, ct1
}

func (hbtp *HalfBootstrapper) evaluateCheby(ct *Ciphertext) *Ciphertext {

	var err error

	cheby := hbtp.sineEvalPoly

	targetScale := hbtp.sinescale

	// Compute the scales that the ciphertext should have before the double angle
	// formula such that after it it has the scale it had before the polynomial
	// evaluation
	for i := 0; i < hbtp.SinRescal; i++ {
		targetScale = math.Sqrt(targetScale * float64(hbtp.SineEvalModuli.Qi[i]))
	}

	// Division by 1/2^r and change of variable for the Chebysehev evaluation
	if hbtp.SinType == Cos1 || hbtp.SinType == Cos2 {
		hbtp.AddConst(ct, -0.5/(complex(hbtp.scFac, 0)*(cheby.b-cheby.a)), ct)
	}

	// Chebyshev evaluation
	if ct, err = hbtp.EvaluateCheby(ct, cheby, targetScale); err != nil {
		panic(err)
	}

	// Double angle
	sqrt2pi := hbtp.sqrt2pi
	for i := 0; i < hbtp.SinRescal; i++ {
		sqrt2pi *= sqrt2pi
		hbtp.MulRelin(ct, ct, ct)
		hbtp.Add(ct, ct, ct)
		hbtp.AddConst(ct, -sqrt2pi, ct)
		if err := hbtp.Rescale(ct, hbtp.ckksEvaluator.scale, ct); err != nil {
			panic(err)
		}
	}

	// ArcSine
	if hbtp.ArcSineDeg > 0 {
		if ct, err = hbtp.EvaluatePoly(ct, hbtp.arcSinePoly, ct.Scale()); err != nil {
			panic(err)
		}
	}

	return ct
}
