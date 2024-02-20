package ckks_fv

import (
	"fmt"
	"math"
	"math/big"

	"HHESoK/rtf_ckks_integration/ring"
	"HHESoK/rtf_ckks_integration/rlwe"
	"HHESoK/rtf_ckks_integration/utils"

	"unsafe"
)

// MFVEvaluator is an interface implementing the public methodes of the eval.
type MFVEvaluator interface {
	Add(op0, op1 Operand, ctOut *Ciphertext)
	AddNew(op0, op1 Operand) (ctOut *Ciphertext)
	AddNoMod(op0, op1 Operand, ctOut *Ciphertext)
	AddNoModNew(op0, op1 Operand) (ctOut *Ciphertext)
	Sub(op0, op1 Operand, ctOut *Ciphertext)
	SubNew(op0, op1 Operand) (ctOut *Ciphertext)
	SubNoMod(op0, op1 Operand, ctOut *Ciphertext)
	SubNoModNew(op0, op1 Operand) (ctOut *Ciphertext)
	Neg(op Operand, ctOut *Ciphertext)
	NegNew(op Operand) (ctOut *Ciphertext)
	Reduce(op Operand, ctOut *Ciphertext)
	ReduceNew(op Operand) (ctOut *Ciphertext)
	MulScalar(op Operand, scalar uint64, ctOut *Ciphertext)
	MulScalarNew(op Operand, scalar uint64) (ctOut *Ciphertext)
	Mul(op0 *Ciphertext, op1 Operand, ctOut *Ciphertext)
	MulNew(op0 *Ciphertext, op1 Operand) (ctOut *Ciphertext)
	Relinearize(ct0 *Ciphertext, ctOut *Ciphertext)
	RelinearizeNew(ct0 *Ciphertext) (ctOut *Ciphertext)
	SwitchKeys(ct0 *Ciphertext, switchKey *SwitchingKey, ctOut *Ciphertext)
	SwitchKeysNew(ct0 *Ciphertext, switchkey *SwitchingKey) (ctOut *Ciphertext)
	RotateColumnsNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext)
	RotateColumns(ct0 *Ciphertext, k int, ctOut *Ciphertext)
	RotateRows(ct0 *Ciphertext, ctOut *Ciphertext)
	RotateRowsNew(ct0 *Ciphertext) (ctOut *Ciphertext)
	InnerSum(ct0 *Ciphertext, ctOut *Ciphertext)
	ShallowCopy() MFVEvaluator
	WithKey(EvaluationKey) MFVEvaluator

	// Modulus Switch
	ModSwitch(ct0, ctOut *Ciphertext)
	ModSwitchMany(ct0, ctOut *Ciphertext, nbModSwitch int)

	// Transform to NTT
	TransformToNTT(ct0, ctOut *Ciphertext)

	// Linear Transformation
	SlotsToCoeffs(ct *Ciphertext, stcModDown []int) (ctOut *Ciphertext)
	SlotsToCoeffsNoModSwitch(ct *Ciphertext) (ctOut *Ciphertext)
	SlotsToCoeffsAutoModSwitch(ct *Ciphertext, noiseEstimator MFVNoiseEstimator) (ctOut *Ciphertext, stcModDown []int)
	LinearTransform(vec *Ciphertext, linearTransform interface{}) (res []*Ciphertext)
	MultiplyByDiabMatrix(vec, res *Ciphertext, matrix *PtDiagMatrixT, c2QiQDecomp, c2QiPDecomp []*ring.Poly)
	MultiplyByDiabMatrixNaive(vec, res *Ciphertext, matrix *PtDiagMatrixT, c2QiQDecomp, c2QiPDecomp []*ring.Poly)
	MultiplyByDiabMatrixBSGS(vec, res *Ciphertext, matrix *PtDiagMatrixT, c2QiQDecomp, c2QiPDecomp []*ring.Poly)
}

// evaluator is a struct that holds the necessary elements to perform the homomorphic operations between ciphertexts and/or plaintexts.
// It also holds a small memory pool used to store intermediate computations.
type mfvEvaluator struct {
	*mfvEvaluatorBase
	*mfvEvaluatorBuffers

	pDcds           [][]*PtDiagMatrixT
	rlk             *RelinearizationKey
	rtks            *RotationKeySet
	permuteNTTIndex map[uint64][]uint64

	baseconverterQ1Q2s []*ring.FastBasisExtender
	baseconverterQ1P   *ring.FastBasisExtender
}

type mfvEvaluatorBase struct {
	params   *Parameters
	ringQ    *ring.Ring
	ringQs   []*ring.Ring
	ringP    *ring.Ring
	ringQMul *ring.Ring

	decomposer *ring.Decomposer

	plainModulus uint64
	pHalf        *big.Int

	deltasMont [][]uint64
}

func newMFVEvaluatorPrecomp(params *Parameters) *mfvEvaluatorBase {
	var err error
	ev := new(mfvEvaluatorBase)

	ev.params = params.Copy()

	ev.plainModulus = params.plainModulus

	if ev.ringQ, err = ring.NewRing(params.N(), params.qi); err != nil {
		panic(err)
	}

	modCount := len(params.qi)
	ev.ringQs = make([]*ring.Ring, modCount)
	for i := 0; i < modCount; i++ {
		if ev.ringQs[i], err = ring.NewRing(params.N(), params.qi[:i+1]); err != nil {
			panic(err)
		}
	}

	// Generates #QiMul primes such that Q * QMul > Q*Q*N
	logQTimesN := ev.ringQ.ModulusBigint.BitLen() + params.LogN()
	var nbQiMul, logQMul int
	for logQMul < logQTimesN {
		nbQiMul++
		logQMul += 61
	}

	qiMul := ring.GenerateNTTPrimesP(61, 2*params.N(), nbQiMul)

	if ev.ringQMul, err = ring.NewRing(params.N(), qiMul); err != nil {
		panic(err)
	}

	ev.pHalf = new(big.Int).Rsh(ev.ringQMul.ModulusBigint, 1)
	ev.deltasMont = make([][]uint64, modCount)
	for i := 0; i < modCount; i++ {
		ev.deltasMont[i] = GenLiftParams(ev.ringQs[i], params.plainModulus)
	}

	if len(params.pi) != 0 {

		if ev.ringP, err = ring.NewRing(params.N(), params.pi); err != nil {
			panic(err)
		}
		ev.decomposer = ring.NewDecomposer(ev.ringQ.Modulus, ev.ringP.Modulus)
	}
	return ev
}

type mfvEvaluatorBuffers struct {
	poolQ    [][]*ring.Poly
	poolQmul [][]*ring.Poly

	poolQKS [4]*ring.Poly
	poolPKS [3]*ring.Poly

	poolP       [5]*ring.Poly
	c2QiQDecomp []*ring.Poly
	c2QiPDecomp []*ring.Poly

	tmpPt *Plaintext
}

func newMFVEvaluatorBuffer(eval *mfvEvaluatorBase) *mfvEvaluatorBuffers {
	evb := new(mfvEvaluatorBuffers)
	evb.poolQ = make([][]*ring.Poly, 4)
	evb.poolQmul = make([][]*ring.Poly, 4)
	for i := 0; i < 4; i++ {
		evb.poolQ[i] = make([]*ring.Poly, 6)
		evb.poolQmul[i] = make([]*ring.Poly, 6)
		for j := 0; j < 6; j++ {
			evb.poolQ[i][j] = eval.ringQ.NewPoly()
			evb.poolQmul[i][j] = eval.ringQMul.NewPoly()
		}
	}
	if eval.ringP != nil {
		evb.poolQKS = [4]*ring.Poly{eval.ringQ.NewPoly(), eval.ringQ.NewPoly(), eval.ringQ.NewPoly(), eval.ringQ.NewPoly()}
		evb.poolPKS = [3]*ring.Poly{eval.ringP.NewPoly(), eval.ringP.NewPoly(), eval.ringP.NewPoly()}

		evb.c2QiQDecomp = make([]*ring.Poly, eval.params.Beta())
		evb.c2QiPDecomp = make([]*ring.Poly, eval.params.Beta())

		for i := 0; i < eval.params.Beta(); i++ {
			evb.c2QiQDecomp[i] = eval.ringQ.NewPoly()
			evb.c2QiPDecomp[i] = eval.ringQ.NewPoly()
		}

		for i := 0; i < 5; i++ {
			evb.poolP[i] = eval.ringP.NewPoly()
		}
	}

	evb.tmpPt = NewPlaintextFV(eval.params)

	return evb
}

// NewMFVEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on ciphertexts and/or plaintexts. It stores a small pool of polynomials
// and ciphertexts that will be used for intermediate values.
func NewMFVEvaluator(params *Parameters, evaluationKey EvaluationKey, pDcdMatrices [][]*PtDiagMatrixT) MFVEvaluator {
	ev := new(mfvEvaluator)
	ev.mfvEvaluatorBase = newMFVEvaluatorPrecomp(params)
	ev.mfvEvaluatorBuffers = newMFVEvaluatorBuffer(ev.mfvEvaluatorBase)

	modCount := len(params.qi)
	ev.baseconverterQ1Q2s = make([]*ring.FastBasisExtender, modCount)
	for i := range ev.baseconverterQ1Q2s {
		ev.baseconverterQ1Q2s[i] = ring.NewFastBasisExtender(ev.ringQs[i], ev.ringQMul)
	}
	if len(params.pi) != 0 {
		ev.baseconverterQ1P = ring.NewFastBasisExtender(ev.ringQ, ev.ringP)
	}
	ev.rlk = evaluationKey.Rlk
	ev.rtks = evaluationKey.Rtks
	if ev.rtks != nil {
		ev.permuteNTTIndex = *ev.permuteNTTIndexesForKeys(ev.rtks)
	}

	ev.pDcds = pDcdMatrices
	return ev
}

func (eval *mfvEvaluator) permuteNTTIndexesForKeys(rtks *RotationKeySet) *map[uint64][]uint64 {
	if rtks == nil {
		return &map[uint64][]uint64{}
	}
	permuteNTTIndex := make(map[uint64][]uint64, len(rtks.Keys))
	for galEl := range rtks.Keys {
		permuteNTTIndex[galEl] = ring.PermuteNTTIndex(galEl, uint64(eval.ringQ.N))
	}
	return &permuteNTTIndex
}

// NewMFVEvaluators creates n evaluators sharing the same read-only data-structures.
func NewMFVEvaluators(params *Parameters, evaluationKey EvaluationKey, pDcdMatrices [][]*PtDiagMatrixT, n int) []MFVEvaluator {
	if n <= 0 {
		return []MFVEvaluator{}
	}
	evas := make([]MFVEvaluator, n, n)
	for i := range evas {
		if i == 0 {
			evas[0] = NewMFVEvaluator(params, evaluationKey, pDcdMatrices)
		} else {
			evas[i] = evas[i-1].ShallowCopy()
		}
	}
	return evas
}

// ShallowCopy creates a shallow copy of this evaluator in which the read-only data-structures are
// shared with the receiver.
func (eval *mfvEvaluator) ShallowCopy() MFVEvaluator {
	modCount := len(eval.params.qi)
	baseconverterQ1Q2s := make([]*ring.FastBasisExtender, modCount)
	for i := range baseconverterQ1Q2s {
		baseconverterQ1Q2s[i] = eval.baseconverterQ1Q2s[i].ShallowCopy()
	}
	return &mfvEvaluator{
		mfvEvaluatorBase:    eval.mfvEvaluatorBase,
		mfvEvaluatorBuffers: newMFVEvaluatorBuffer(eval.mfvEvaluatorBase),
		baseconverterQ1Q2s:  baseconverterQ1Q2s,
		baseconverterQ1P:    eval.baseconverterQ1P.ShallowCopy(),
		rlk:                 eval.rlk,
		rtks:                eval.rtks,
		pDcds:               eval.pDcds,
	}
}

// ShallowCopyWithKey creates a shallow copy of this evaluator in which the read-only data-structures are
// shared with the receiver but the EvaluationKey is evaluationKey.
func (eval *mfvEvaluator) WithKey(evaluationKey EvaluationKey) MFVEvaluator {
	return &mfvEvaluator{
		mfvEvaluatorBase:    eval.mfvEvaluatorBase,
		mfvEvaluatorBuffers: eval.mfvEvaluatorBuffers,
		baseconverterQ1Q2s:  eval.baseconverterQ1Q2s,
		baseconverterQ1P:    eval.baseconverterQ1P,
		rlk:                 evaluationKey.Rlk,
		rtks:                evaluationKey.Rtks,
	}
}

// Add adds op0 to op1 and returns the result in ctOut.
func (eval *mfvEvaluator) Add(op0, op1 Operand, ctOut *Ciphertext) {
	if op0.Level() != op1.Level() {
		panic("cannot Add: inputs should have the same level")
	}

	level := op0.Level()
	el0, el1, elOut := eval.getElemAndCheckBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()), true)
	eval.evaluateInPlaceBinaryLvl(level, el0, el1, elOut, eval.ringQ.AddLvl)
}

// AddNew adds op0 to op1 and creates a new element ctOut to store the result.
func (eval *mfvEvaluator) AddNew(op0, op1 Operand) (ctOut *Ciphertext) {
	if op0.Level() != op1.Level() {
		panic("cannot AddNew: inputs should have the same level")
	}

	level := op0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, utils.MaxInt(op0.Degree(), op1.Degree()), level)
	eval.Add(op0, op1, ctOut)
	return
}

// AddNoMod adds op0 to op1 without modular reduction, and returns the result in cOut.
func (eval *mfvEvaluator) AddNoMod(op0, op1 Operand, ctOut *Ciphertext) {
	level := op0.Level()
	if op1.Level() != level || ctOut.Level() != level {
		panic("cannot AddNoMod: inputs and output should have the same level")
	}
	el0, el1, elOut := eval.getElemAndCheckBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()), true)
	eval.evaluateInPlaceBinaryLvl(level, el0, el1, elOut, eval.ringQ.AddNoModLvl)
}

// AddNoModNew adds op0 to op1 without modular reduction and creates a new element ctOut to store the result.
func (eval *mfvEvaluator) AddNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	if op0.Level() != op1.Level() {
		panic("cannot AddNoModNew: inputs should have the same level")
	}

	level := op0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, utils.MaxInt(op0.Degree(), op1.Degree()), level)
	eval.AddNoMod(op0, op1, ctOut)
	return
}

// Sub subtracts op1 from op0 and returns the result in cOut.
func (eval *mfvEvaluator) Sub(op0, op1 Operand, ctOut *Ciphertext) {
	level := op0.Level()
	if op1.Level() != level || ctOut.Level() != level {
		panic("cannot Sub: inputs and output should have the same level")
	}
	el0, el1, elOut := eval.getElemAndCheckBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()), true)
	eval.evaluateInPlaceBinaryLvl(level, el0, el1, elOut, eval.ringQ.SubLvl)

	if el0.Degree() < el1.Degree() {
		for i := el0.Degree() + 1; i < el1.Degree()+1; i++ {
			eval.ringQ.NegLvl(level, ctOut.Value()[i], ctOut.Value()[i])
		}
	}
}

// SubNew subtracts op1 from op0 and creates a new element ctOut to store the result.
func (eval *mfvEvaluator) SubNew(op0, op1 Operand) (ctOut *Ciphertext) {
	if op0.Level() != op1.Level() {
		panic("cannot SubNew: inputs should have the same level")
	}

	level := op0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, utils.MaxInt(op0.Degree(), op1.Degree()), level)
	eval.Sub(op0, op1, ctOut)
	return
}

// SubNoMod subtracts op1 from op0 without modular reduction and returns the result on ctOut.
func (eval *mfvEvaluator) SubNoMod(op0, op1 Operand, ctOut *Ciphertext) {
	level := op0.Level()
	if op1.Level() != level || ctOut.Level() != level {
		panic("cannot SubNoMod: inputs and output should have the same level")
	}

	el0, el1, elOut := eval.getElemAndCheckBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()), true)

	eval.evaluateInPlaceBinaryLvl(level, el0, el1, elOut, eval.ringQ.SubNoModLvl)

	if el0.Degree() < el1.Degree() {
		for i := el0.Degree() + 1; i < el1.Degree()+1; i++ {
			eval.ringQ.NegLvl(level, ctOut.Value()[i], ctOut.Value()[i])
		}
	}
}

// SubNoModNew subtracts op1 from op0 without modular reduction and creates a new element ctOut to store the result.
func (eval *mfvEvaluator) SubNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	if op0.Level() != op1.Level() {
		panic("cannot SubNoModNew: inputs should have the same level")
	}

	level := op0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, utils.MaxInt(op0.Degree(), op1.Degree()), level)
	eval.SubNoMod(op0, op1, ctOut)
	return
}

// Neg negates op and returns the result in ctOut.
func (eval *mfvEvaluator) Neg(op Operand, ctOut *Ciphertext) {
	if op.Level() != ctOut.Level() {
		panic("cannot Neg: input and output should have the same level")
	}

	level := op.Level()
	el0, elOut := eval.getElemAndCheckUnary(op, ctOut, op.Degree())
	evaluateInPlaceUnaryLvl(level, el0, elOut, eval.ringQ.NegLvl)
}

// NegNew negates op and creates a new element to store the result.
func (eval *mfvEvaluator) NegNew(op Operand) (ctOut *Ciphertext) {
	level := op.Level()
	ctOut = NewCiphertextFVLvl(eval.params, op.Degree(), level)
	eval.Neg(op, ctOut)
	return ctOut
}

// Reduce applies a modular reduction to op and returns the result in ctOut.
func (eval *mfvEvaluator) Reduce(op Operand, ctOut *Ciphertext) {
	if op.Level() != ctOut.Level() {
		panic("cannot Reduce: input and output ctxt should have the same level")
	}

	level := op.Level()
	el0, elOut := eval.getElemAndCheckUnary(op, ctOut, op.Degree())
	evaluateInPlaceUnaryLvl(level, el0, elOut, eval.ringQ.ReduceLvl)
}

// ReduceNew applies a modular reduction to op and creates a new element ctOut to store the result.
func (eval *mfvEvaluator) ReduceNew(op Operand) (ctOut *Ciphertext) {
	level := op.Level()
	ctOut = NewCiphertextFVLvl(eval.params, op.Degree(), level)
	eval.Reduce(op, ctOut)
	return ctOut
}

// MulScalar multiplies op by a uint64 scalar and returns the result in ctOut.
func (eval *mfvEvaluator) MulScalar(op Operand, scalar uint64, ctOut *Ciphertext) {
	if op.Level() != ctOut.Level() {
		panic("cannot MulScalar: input and output ctxt should have the same level")
	}

	level := op.Level()
	el0, elOut := eval.getElemAndCheckUnary(op, ctOut, op.Degree())
	fun := func(lvl int, el, elOut *ring.Poly) { eval.ringQ.MulScalarLvl(lvl, el, scalar, elOut) }
	evaluateInPlaceUnaryLvl(level, el0, elOut, fun)
}

// MulScalarNew multiplies op by a uint64 scalar and creates a new element ctOut to store the result.
func (eval *mfvEvaluator) MulScalarNew(op Operand, scalar uint64) (ctOut *Ciphertext) {
	level := op.Level()
	ctOut = NewCiphertextFVLvl(eval.params, op.Degree(), level)
	eval.MulScalar(op, scalar, ctOut)
	return
}

// tensorAndRescale computes (ct0 x ct1) * (t/Q) and stores the result in ctOut.
func (eval *mfvEvaluator) tensorAndRescale(ct0, ct1, ctOut *Element) {
	level := ct0.Level()
	if ct1.Level() != level || ctOut.Level() != level {
		panic("cannot tensorAndRescale: inputs and output should have the same level")
	}

	c0Q1 := eval.poolQ[0]
	c0Q2 := eval.poolQmul[0]

	c1Q1 := eval.poolQ[1]
	c1Q2 := eval.poolQmul[1]

	// Prepares the ciphertexts for the Tensoring by extending their
	// basis from Q to QP and transforming them to NTT form
	eval.modUpAndNTT(ct0, c0Q1, c0Q2)

	if ct0 != ct1 {
		eval.modUpAndNTT(ct1, c1Q1, c1Q2)
	}

	// Tensoring: multiplies each elements of the ciphertexts together
	// and adds them to their corresponding position in the new ciphertext
	// based on their respective degree

	// Case where both Elements are of degree 1
	if ct0.Degree() == 1 && ct1.Degree() == 1 {
		eval.tensoreLowDeg(ct0, ct1)
		// Case where at least one element is not of degree 1
	} else {
		eval.tensortLargeDeg(ct0, ct1)
	}

	eval.quantize(ctOut)
}

func (eval *mfvEvaluator) modUpAndNTT(ct *Element, cQ, cQMul []*ring.Poly) {
	level := ct.Level()
	for i := range ct.value {
		eval.baseconverterQ1Q2s[level].ModUpSplitQP(level, ct.value[i], cQMul[i])
		eval.ringQ.NTTLazyLvl(level, ct.value[i], cQ[i])
		eval.ringQMul.NTTLazy(cQMul[i], cQMul[i])
	}
}

func (eval *mfvEvaluator) tensoreLowDeg(ct0, ct1 *Element) {

	if ct0.Level() != ct1.Level() {
		panic("cannot tensoreLowDeg: inputs should have the same level")
	}
	level := ct0.Level()

	c0Q1 := eval.poolQ[0]
	c0Q2 := eval.poolQmul[0]

	c1Q1 := eval.poolQ[1]
	c1Q2 := eval.poolQmul[1]

	c2Q1 := eval.poolQ[2]
	c2Q2 := eval.poolQmul[2]

	c00Q := eval.poolQ[3][0]
	c00Q2 := eval.poolQmul[3][0]
	c01Q := eval.poolQ[3][1]
	c01P := eval.poolQmul[3][1]

	eval.ringQ.MFormLvl(level, c0Q1[0], c00Q)
	eval.ringQMul.MForm(c0Q2[0], c00Q2)

	eval.ringQ.MFormLvl(level, c0Q1[1], c01Q)
	eval.ringQMul.MForm(c0Q2[1], c01P)

	// Squaring case
	if ct0 == ct1 {

		// c0 = c0[0]*c0[0]
		eval.ringQ.MulCoeffsMontgomeryLvl(level, c00Q, c0Q1[0], c2Q1[0])
		eval.ringQMul.MulCoeffsMontgomery(c00Q2, c0Q2[0], c2Q2[0])

		// c1 = 2*c0[0]*c0[1]
		eval.ringQ.MulCoeffsMontgomeryLvl(level, c00Q, c0Q1[1], c2Q1[1])
		eval.ringQMul.MulCoeffsMontgomery(c00Q2, c0Q2[1], c2Q2[1])

		eval.ringQ.AddNoModLvl(level, c2Q1[1], c2Q1[1], c2Q1[1])
		eval.ringQMul.AddNoMod(c2Q2[1], c2Q2[1], c2Q2[1])

		// c2 = c0[1]*c0[1]
		eval.ringQ.MulCoeffsMontgomeryLvl(level, c01Q, c0Q1[1], c2Q1[2])
		eval.ringQMul.MulCoeffsMontgomery(c01P, c0Q2[1], c2Q2[2])

		// Normal case
	} else {

		// c0 = c0[0]*c1[0]
		eval.ringQ.MulCoeffsMontgomeryLvl(level, c00Q, c1Q1[0], c2Q1[0])
		eval.ringQMul.MulCoeffsMontgomery(c00Q2, c1Q2[0], c2Q2[0])

		// c1 = c0[0]*c1[1] + c0[1]*c1[0]
		eval.ringQ.MulCoeffsMontgomeryLvl(level, c00Q, c1Q1[1], c2Q1[1])
		eval.ringQMul.MulCoeffsMontgomery(c00Q2, c1Q2[1], c2Q2[1])

		eval.ringQ.MulCoeffsMontgomeryAndAddNoModLvl(level, c01Q, c1Q1[0], c2Q1[1])
		eval.ringQMul.MulCoeffsMontgomeryAndAddNoMod(c01P, c1Q2[0], c2Q2[1])

		// c2 = c0[1]*c1[1]
		eval.ringQ.MulCoeffsMontgomeryLvl(level, c01Q, c1Q1[1], c2Q1[2])
		eval.ringQMul.MulCoeffsMontgomery(c01P, c1Q2[1], c2Q2[2])
	}
}

func (eval *mfvEvaluator) tensortLargeDeg(ct0, ct1 *Element) {

	if ct0.Level() != ct1.Level() {
		panic("cannot tensortLargeDeg: inputs should have the same level")
	}
	level := ct0.Level()

	c0Q1 := eval.poolQ[0]
	c0Q2 := eval.poolQmul[0]

	c1Q1 := eval.poolQ[1]
	c1Q2 := eval.poolQmul[1]

	c2Q1 := eval.poolQ[2]
	c2Q2 := eval.poolQmul[2]

	for i := 0; i < ct0.Degree()+ct1.Degree()+1; i++ {
		c2Q1[i].Zero()
		c2Q2[i].Zero()
	}

	// Squaring case
	if ct0 == ct1 {

		c00Q1 := eval.poolQ[3]
		c00Q2 := eval.poolQmul[3]

		for i := range ct0.value {
			eval.ringQ.MFormLvl(level, c0Q1[i], c00Q1[i])
			eval.ringQMul.MForm(c0Q2[i], c00Q2[i])
		}

		for i := 0; i < ct0.Degree()+1; i++ {
			for j := i + 1; j < ct0.Degree()+1; j++ {
				eval.ringQ.MulCoeffsMontgomeryLvl(level, c00Q1[i], c0Q1[j], c2Q1[i+j])
				eval.ringQMul.MulCoeffsMontgomery(c00Q2[i], c0Q2[j], c2Q2[i+j])

				eval.ringQ.AddLvl(level, c2Q1[i+j], c2Q1[i+j], c2Q1[i+j])
				eval.ringQMul.Add(c2Q2[i+j], c2Q2[i+j], c2Q2[i+j])
			}
		}

		for i := 0; i < ct0.Degree()+1; i++ {
			eval.ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00Q1[i], c0Q1[i], c2Q1[i<<1])
			eval.ringQMul.MulCoeffsMontgomeryAndAdd(c00Q2[i], c0Q2[i], c2Q2[i<<1])
		}

		// Normal case
	} else {
		for i := range ct0.value {
			eval.ringQ.MFormLvl(level, c0Q1[i], c0Q1[i])
			eval.ringQMul.MForm(c0Q2[i], c0Q2[i])
			for j := range ct1.value {
				eval.ringQ.MulCoeffsMontgomeryAndAddLvl(level, c0Q1[i], c1Q1[j], c2Q1[i+j])
				eval.ringQMul.MulCoeffsMontgomeryAndAdd(c0Q2[i], c1Q2[j], c2Q2[i+j])
			}
		}
	}
}

func (eval *mfvEvaluator) quantize(ctOut *Element) {

	level := ctOut.Level()
	levelQMul := len(eval.ringQMul.Modulus) - 1

	c2Q1 := eval.poolQ[2]
	c2Q2 := eval.poolQmul[2]

	// Applies the inverse NTT to the ciphertext, scales down the ciphertext
	// by t/q and reduces its basis from QP to Q
	for i := range ctOut.value {
		eval.ringQ.InvNTTLazyLvl(level, c2Q1[i], c2Q1[i])
		eval.ringQMul.InvNTTLazy(c2Q2[i], c2Q2[i])

		// Extends the basis Q of ct(x) to the basis P and Divides (ct(x)Q -> P) by Q
		eval.baseconverterQ1Q2s[level].ModDownSplitQP(level, levelQMul, c2Q1[i], c2Q2[i], c2Q2[i])

		// Centers (ct(x)Q -> P)/Q by (P-1)/2 and extends ((ct(x)Q -> P)/Q) to the basis Q
		eval.ringQMul.AddScalarBigint(c2Q2[i], eval.pHalf, c2Q2[i])
		eval.baseconverterQ1Q2s[level].ModUpSplitPQ(levelQMul, c2Q2[i], ctOut.value[i])
		eval.ringQ.SubScalarBigintLvl(level, ctOut.value[i], eval.pHalf, ctOut.value[i])

		// Option (2) (ct(x)/Q)*T, doing so only requires that Q*P > Q*Q, faster but adds error ~|T|
		eval.ringQ.MulScalarLvl(level, ctOut.value[i], eval.plainModulus, ctOut.value[i])
	}
}

// Mul multiplies op0 by op1 and returns the result in ctOut.
func (eval *mfvEvaluator) Mul(op0 *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	el0, el1, elOut := eval.getElemAndCheckBinary(op0, op1, ctOut, op0.Degree()+op1.Degree(), false)
	switch op1 := op1.(type) {
	case *PlaintextMul:
		eval.mulPlaintextMul(op0, op1, ctOut)
	case *PlaintextRingT:
		eval.mulPlaintextRingT(op0, op1, ctOut)
	case *Plaintext, *Ciphertext:
		eval.tensorAndRescale(el0, el1, elOut)
	default:
		panic(fmt.Errorf("invalid operand type for Mul: %T", op1))
	}

}

func (eval *mfvEvaluator) mulPlaintextMul(ct0 *Ciphertext, ptRt *PlaintextMul, ctOut *Ciphertext) {
	if ct0.Level() != ptRt.Level() {
		panic("cannot mulPlaintextMul: ct0 and ptRt should have the same level")
	}
	level := ct0.Level()
	for i := range ct0.value {
		eval.ringQ.NTTLazyLvl(level, ct0.value[i], ctOut.value[i])
		eval.ringQ.MulCoeffsMontgomeryConstantLvl(level, ctOut.value[i], ptRt.value, ctOut.value[i])
		eval.ringQ.InvNTTLvl(level, ctOut.value[i], ctOut.value[i])
	}
}

func (eval *mfvEvaluator) mulPlaintextRingT(ct0 *Ciphertext, ptRt *PlaintextRingT, ctOut *Ciphertext) {
	level := ct0.Level()
	ringQ := eval.ringQ

	coeffs := ptRt.value.Coeffs[0]
	coeffsNTT := eval.poolQ[0][0].Coeffs[0]

	for i := range ct0.value {

		// Copies the inputCT on the outputCT and switches to the NTT domain
		eval.ringQ.NTTLazyLvl(level, ct0.value[i], ctOut.value[i])

		// Switches the outputCT in the Montgomery domain
		eval.ringQ.MFormLvl(level, ctOut.value[i], ctOut.value[i])

		// For each qi in Q
		for j := 0; j < level+1; j++ {

			tmp := ctOut.value[i].Coeffs[j]
			qi := ringQ.Modulus[j]
			nttPsi := ringQ.NttPsi[j]
			bredParams := ringQ.BredParams[j]
			mredParams := ringQ.MredParams[j]

			// Transforms the plaintext in the NTT domain of that qi
			ring.NTTLazy(coeffs, coeffsNTT, ringQ.N, nttPsi, qi, mredParams, bredParams)

			// Multiplies NTT_qi(pt) * NTT_qi(ct)
			for k := 0; k < eval.ringQ.N; k = k + 8 {

				x := (*[8]uint64)(unsafe.Pointer(&coeffsNTT[k]))
				z := (*[8]uint64)(unsafe.Pointer(&tmp[k]))

				z[0] = ring.MRed(z[0], x[0], qi, mredParams)
				z[1] = ring.MRed(z[1], x[1], qi, mredParams)
				z[2] = ring.MRed(z[2], x[2], qi, mredParams)
				z[3] = ring.MRed(z[3], x[3], qi, mredParams)
				z[4] = ring.MRed(z[4], x[4], qi, mredParams)
				z[5] = ring.MRed(z[5], x[5], qi, mredParams)
				z[6] = ring.MRed(z[6], x[6], qi, mredParams)
				z[7] = ring.MRed(z[7], x[7], qi, mredParams)
			}
		}

		// Switches the ciphertext out of the NTT domain
		eval.ringQ.InvNTTLvl(level, ctOut.value[i], ctOut.value[i])
	}
}

// MulNew multiplies op0 by op1 and creates a new element ctOut to store the result.
func (eval *mfvEvaluator) MulNew(op0 *Ciphertext, op1 Operand) (ctOut *Ciphertext) {
	level := op0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, op0.Degree()+op1.Degree(), level)
	eval.Mul(op0, op1, ctOut)
	return
}

// relinearize is a method common to Relinearize and RelinearizeNew. It switches ct0 to the NTT domain, applies the keyswitch, and returns the result out of the NTT domain.
func (eval *mfvEvaluator) relinearize(ct0 *Ciphertext, ctOut *Ciphertext) {

	if ct0.Level() != ctOut.Level() {
		panic("cannot relinearize: input and output should have the same level")
	}
	level := ct0.Level()

	if ctOut != ct0 {
		eval.ringQ.CopyLvl(level, ct0.value[0], ctOut.value[0])
		eval.ringQ.CopyLvl(level, ct0.value[1], ctOut.value[1])
	}

	for deg := uint64(ct0.Degree()); deg > 1; deg-- {
		eval.switchKeysInPlace(ct0.value[deg], eval.rlk.Keys[deg-2], eval.poolQKS[1], eval.poolQKS[2])
		eval.ringQ.AddLvl(level, ctOut.value[0], eval.poolQKS[1], ctOut.value[0])
		eval.ringQ.AddLvl(level, ctOut.value[1], eval.poolQKS[2], ctOut.value[1])
	}

	ctOut.SetValue(ctOut.value[:2])
}

// Relinearize relinearizes the ciphertext ct0 of degree > 1 until it is of degree 1, and returns the result in cOut.
//
// It requires a correct evaluation key as additional input:
//
// - it must match the secret-key that was used to create the public key under which the current ct0 is encrypted.
//
// - it must be of degree high enough to relinearize the input ciphertext to degree 1 (e.g., a ciphertext
// of degree 3 will require that the evaluation key stores the keys for both degree 3 and degree 2 ciphertexts).
func (eval *mfvEvaluator) Relinearize(ct0 *Ciphertext, ctOut *Ciphertext) {

	if ct0.Level() != ctOut.Level() {
		panic("cannot Relinearize: input and output should have the same level")
	}

	if eval.rlk == nil {
		panic("evaluator has no relinearization key")
	}

	if ct0.Degree()-1 > len(eval.rlk.Keys) {
		panic("input ciphertext degree is too large to allow relinearization with the evluator's relinearization key")
	}

	if ct0.Degree() < 2 {
		if ct0 != ctOut {
			ctOut.Copy(ct0.El())
		}
	} else {
		eval.relinearize(ct0, ctOut)
	}
}

// RelinearizeNew relinearizes the ciphertext ct0 of degree > 1 until it is of degree 1, and creates a new ciphertext to store the result.
//
// Requires a correct evaluation key as additional input:
//
// - it must match the secret-key that was used to create the public key under which the current ct0 is encrypted
//
// - it must be of degree high enough to relinearize the input ciphertext to degree 1 (e.g., a ciphertext
// of degree 3 will require that the evaluation key stores the keys for both degree 3 and degree 2 ciphertexts).
func (eval *mfvEvaluator) RelinearizeNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	level := ct0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, 1, level)
	eval.Relinearize(ct0, ctOut)
	return
}

// SwitchKeys applies the key-switching procedure to the ciphertext ct0 and returns the result in ctOut. It requires as an additional input a valid switching-key:
// it must encrypt the target key under the public key under which ct0 is currently encrypted.
func (eval *mfvEvaluator) SwitchKeys(ct0 *Ciphertext, switchKey *SwitchingKey, ctOut *Ciphertext) {

	if ct0.Level() != ctOut.Level() {
		panic("cannot SwitchKeys: input and output should have the same level")
	}
	level := ct0.Level()

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot SwitchKeys: input and output must be of degree 1 to allow key switching")
	}

	eval.switchKeysInPlace(ct0.value[1], &switchKey.SwitchingKey, eval.poolQKS[1], eval.poolQKS[2])

	eval.ringQ.AddLvl(level, ct0.value[0], eval.poolQKS[1], ctOut.value[0])
	eval.ringQ.CopyLvl(level, eval.poolQKS[2], ctOut.value[1])
}

// SwitchKeysNew applies the key-switching procedure to the ciphertext ct0 and creates a new ciphertext to store the result. It requires as an additional input a valid switching-key:
// it must encrypt the target key under the public key under which ct0 is currently encrypted.
func (eval *mfvEvaluator) SwitchKeysNew(ct0 *Ciphertext, switchkey *SwitchingKey) (ctOut *Ciphertext) {
	level := ct0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, 1, level)
	eval.SwitchKeys(ct0, switchkey, ctOut)
	return
}

// RotateColumns rotates the columns of ct0 by k positions to the left and returns the result in ctOut. As an additional input it requires a RotationKeys struct:
//
// - it must either store all the left and right power-of-2 rotations or the specific rotation that is requested.
//
// If only the power-of-two rotations are stored, the numbers k and n/2-k will be decomposed in base-2 and the rotation with the lowest
// hamming weight will be chosen; then the specific rotation will be computed as a sum of powers of two rotations.
func (eval *mfvEvaluator) RotateColumns(ct0 *Ciphertext, k int, ctOut *Ciphertext) {

	if ct0.Level() != ctOut.Level() {
		panic("cannot RotateColumns: input and output should have the same level")
	}

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot RotateColumns: input and or output must be of degree 1")
	}

	if k == 0 {

		ctOut.Copy(ct0.El())

	} else {

		galElL := eval.params.GaloisElementForColumnRotationBy(k)
		// Looks in the rotation key if the corresponding rotation has been generated or if the input is a plaintext
		if swk, inSet := eval.rtks.GetRotationKey(galElL); inSet {

			eval.permute(ct0, galElL, swk, ctOut)

		} else {
			panic(fmt.Errorf("evaluator has no rotation key for rotation by %d", k))
		}
	}
}

// RotateColumnsNew applies RotateColumns and returns the result in a new Ciphertext.
func (eval *mfvEvaluator) RotateColumnsNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext) {
	level := ct0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, 1, level)
	eval.RotateColumns(ct0, k, ctOut)
	return
}

// RotateRows rotates the rows of ct0 and returns the result in ctOut.
func (eval *mfvEvaluator) RotateRows(ct0 *Ciphertext, ctOut *Ciphertext) {

	if ct0.Level() != ctOut.Level() {
		panic("cannot RotateRows: input and output should have the same level")
	}

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot RotateRows: input and/or output must be of degree 1")
	}

	galEl := eval.params.GaloisElementForRowRotation()

	if key, inSet := eval.rtks.GetRotationKey(galEl); inSet {
		eval.permute(ct0, galEl, key, ctOut)
	} else {
		panic("evaluator has no rotation key for row rotation")
	}
}

// RotateRowsNew rotates the rows of ct0 and returns the result a new Ciphertext.
func (eval *mfvEvaluator) RotateRowsNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	level := ct0.Level()
	ctOut = NewCiphertextFVLvl(eval.params, 1, level)
	eval.RotateRows(ct0, ctOut)
	return
}

// InnerSum computes the inner sum of ct0 and returns the result in ctOut. It requires a rotation key storing all the left powers of two rotations.
// The resulting vector will be of the form [sum, sum, .., sum, sum].
func (eval *mfvEvaluator) InnerSum(ct0 *Ciphertext, ctOut *Ciphertext) {

	if ct0.Level() != ctOut.Level() {
		panic("cannot Innersum: input and output should have the same level")
	}

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot InnerSum: input and output must be of degree 1")
	}

	level := ct0.Level()
	cTmp := NewCiphertextFVLvl(eval.params, 1, level)

	ctOut.Copy(ct0.El())

	for i := 1; i < int(eval.ringQ.N>>1); i <<= 1 {
		eval.RotateColumns(ctOut, i, cTmp)
		eval.Add(cTmp, ctOut, ctOut.Ciphertext())
	}

	eval.RotateRows(ctOut, cTmp)
	eval.Add(ctOut, cTmp, ctOut)
}

// permute performs a column rotation on ct0 and returns the result in ctOut
func (eval *mfvEvaluator) permute(ct0 *Ciphertext, generator uint64, switchKey *rlwe.SwitchingKey, ctOut *Ciphertext) {

	level := ct0.Level()
	eval.switchKeysInPlace(ct0.value[1], switchKey, eval.poolQKS[1], eval.poolQKS[2])

	eval.ringQ.AddLvl(level, eval.poolQKS[1], ct0.value[0], eval.poolQKS[1])

	eval.ringQ.PermuteLvl(level, eval.poolQKS[1], generator, ctOut.value[0])
	eval.ringQ.PermuteLvl(level, eval.poolQKS[2], generator, ctOut.value[1])
}

// switchKeys applies the general key-switching procedure of the form [c0 + cx*evakey[0], c1 + cx*evakey[1]]
func (eval *mfvEvaluator) switchKeysInPlace(cx *ring.Poly, evakey *rlwe.SwitchingKey, pool2Q, pool3Q *ring.Poly) {

	ringQ := eval.ringQ
	ringP := eval.ringP

	pool2P := eval.poolPKS[1]
	pool3P := eval.poolPKS[2]

	level := cx.Level()

	c2QiQ := eval.poolQKS[0]
	c2QiP := eval.poolPKS[0]
	c2 := eval.poolQKS[3]

	evakey0Q := new(ring.Poly)
	evakey1Q := new(ring.Poly)
	evakey0P := new(ring.Poly)
	evakey1P := new(ring.Poly)

	// We switch the element on which the key-switching operation will be conducted out of the NTT domain
	ringQ.NTTLazyLvl(level, cx, c2)

	var reduce int

	// Key switching with CRT decomposition for the Qi
	beta := int(math.Ceil(float64(level+1) / float64(eval.params.Alpha())))
	for i := 0; i < beta; i++ {

		eval.decomposeAndSplitNTT(level, i, c2, cx, c2QiQ, c2QiP)

		evakey0Q.Coeffs = evakey.Value[i][0].Coeffs[:level+1]
		evakey1Q.Coeffs = evakey.Value[i][1].Coeffs[:level+1]
		evakey0P.Coeffs = evakey.Value[i][0].Coeffs[len(ringQ.Modulus):]
		evakey1P.Coeffs = evakey.Value[i][1].Coeffs[len(ringQ.Modulus):]

		if i == 0 {
			ringQ.MulCoeffsMontgomeryLvl(level, evakey0Q, c2QiQ, pool2Q)
			ringQ.MulCoeffsMontgomeryLvl(level, evakey1Q, c2QiQ, pool3Q)
			ringP.MulCoeffsMontgomery(evakey0P, c2QiP, pool2P)
			ringP.MulCoeffsMontgomery(evakey1P, c2QiP, pool3P)
		} else {
			ringQ.MulCoeffsMontgomeryAndAddNoModLvl(level, evakey0Q, c2QiQ, pool2Q)
			ringQ.MulCoeffsMontgomeryAndAddNoModLvl(level, evakey1Q, c2QiQ, pool3Q)
			ringP.MulCoeffsMontgomeryAndAddNoMod(evakey0P, c2QiP, pool2P)
			ringP.MulCoeffsMontgomeryAndAddNoMod(evakey1P, c2QiP, pool3P)
		}

		if reduce&3 == 3 {
			ringQ.ReduceLvl(level, pool2Q, pool2Q)
			ringQ.ReduceLvl(level, pool3Q, pool3Q)
			ringP.Reduce(pool2P, pool2P)
			ringP.Reduce(pool3P, pool3P)
		}

		reduce++
	}

	if (reduce-1)&3 != 3 {
		ringQ.ReduceLvl(level, pool2Q, pool2Q)
		ringQ.ReduceLvl(level, pool3Q, pool3Q)
		ringP.Reduce(pool2P, pool2P)
		ringP.Reduce(pool3P, pool3P)
	}

	ringQ.InvNTTLazyLvl(level, pool2Q, pool2Q)
	ringQ.InvNTTLazyLvl(level, pool3Q, pool3Q)
	ringP.InvNTTLazy(pool2P, pool2P)
	ringP.InvNTTLazy(pool3P, pool3P)

	eval.baseconverterQ1P.ModDownSplitPQ(level, pool2Q, pool2P, pool2Q)
	eval.baseconverterQ1P.ModDownSplitPQ(level, pool3Q, pool3P, pool3Q)
}
func (eval *mfvEvaluator) getRingQElem(op Operand) *Element {
	switch o := op.(type) {
	case *Ciphertext, *Plaintext:
		return o.El()
	case *PlaintextRingT:
		level := op.Level()
		fvScaleUp(eval.ringQs[level], eval.deltasMont[level], o.value, eval.tmpPt.value)
		return eval.tmpPt.Element
	default:
		panic(fmt.Errorf("invalid operand type for operation: %T", o))
	}
}

// getElemAndCheckBinary unwraps the elements from the operands and checks that the receiver has sufficiently large degree.
func (eval *mfvEvaluator) getElemAndCheckBinary(op0, op1, opOut Operand, opOutMinDegree int, ensureRingQ bool) (el0, el1, elOut *Element) {
	if op0 == nil || op1 == nil || opOut == nil {
		panic("operands cannot be nil")
	}

	if op0.Degree()+op1.Degree() == 0 {
		panic("operands cannot be both plaintexts")
	}

	if opOut.Degree() < opOutMinDegree {
		panic("receiver operand degree is too small")
	}

	if ensureRingQ {
		return eval.getRingQElem(op0), eval.getRingQElem(op1), opOut.El() // lifts from Rt to Rq if necessary
	}

	return op0.El(), op1.El(), opOut.El()
}

func (eval *mfvEvaluator) getElemAndCheckUnary(op0, opOut Operand, opOutMinDegree int) (el0, elOut *Element) {
	if op0 == nil || opOut == nil {
		panic("operand cannot be nil")
	}

	if op0.Degree() == 0 {
		panic("operand cannot be plaintext")
	}

	if opOut.Degree() < opOutMinDegree {
		panic("receiver operand degree is too small")
	}
	el0, elOut = op0.El(), opOut.El()
	return
}

// evaluateInPlaceBinary applies the provided function in place on el0 and el1 and returns the result in elOut.
func (eval *mfvEvaluator) evaluateInPlaceBinary(el0, el1, elOut *Element, evaluate func(*ring.Poly, *ring.Poly, *ring.Poly)) {

	smallest, largest, _ := getSmallestLargest(el0, el1)

	for i := 0; i < smallest.Degree()+1; i++ {
		evaluate(el0.value[i], el1.value[i], elOut.value[i])
	}

	// If the inputs degrees differ, it copies the remaining degree on the receiver.
	if largest != nil && largest != elOut { // checks to avoid unnecessary work.
		for i := smallest.Degree() + 1; i < largest.Degree()+1; i++ {
			elOut.value[i].Copy(largest.value[i])
		}
	}
}

// evaluateInPlaceBinaryLvl applies the provided function in place on el0 and el1 on given level and returns the result in elOut.
func (eval *mfvEvaluator) evaluateInPlaceBinaryLvl(level int, el0, el1, elOut *Element, evaluate func(int, *ring.Poly, *ring.Poly, *ring.Poly)) {
	smallest, largest, _ := getSmallestLargest(el0, el1)

	for i := 0; i < smallest.Degree()+1; i++ {
		evaluate(level, el0.value[i], el1.value[i], elOut.value[i])
	}

	// If the inputs degree differ, it copies the remaining degree on the receiver.
	if largest != nil && largest != elOut { // checks to avoid unnecessary work.
		for i := smallest.Degree() + 1; i < largest.Degree()+1; i++ {
			elOut.value[i].Copy(largest.value[i])
		}
	}
}

// evaluateInPlaceUnaryLvl applies the provided function in place on el0 on given level and returns the result in elOut.
func evaluateInPlaceUnaryLvl(level int, el0, elOut *Element, evaluate func(int, *ring.Poly, *ring.Poly)) {
	for i := range el0.value {
		evaluate(level, el0.value[i], elOut.value[i])
	}
}

// decomposeAndSplitNTT decomposes the input polynomial into the target CRT basis.
func (eval *mfvEvaluator) decomposeAndSplitNTT(level, beta int, c2NTT, c2InvNTT, c2QiQ, c2QiP *ring.Poly) {

	ringQ := eval.ringQ
	ringP := eval.ringP

	eval.decomposer.DecomposeAndSplit(level, beta, c2InvNTT, c2QiQ, c2QiP)

	p0idxst := beta * eval.params.Alpha()
	p0idxed := p0idxst + eval.decomposer.Xalpha()[beta]

	// c2_qi = cx mod qi mod qi
	for x := 0; x < level+1; x++ {

		qi := ringQ.Modulus[x]
		nttPsi := ringQ.NttPsi[x]
		bredParams := ringQ.BredParams[x]
		mredParams := ringQ.MredParams[x]

		if p0idxst <= x && x < p0idxed {
			p0tmp := c2NTT.Coeffs[x]
			p1tmp := c2QiQ.Coeffs[x]
			for j := 0; j < ringQ.N; j++ {
				p1tmp[j] = p0tmp[j]
			}
		} else {
			ring.NTTLazy(c2QiQ.Coeffs[x], c2QiQ.Coeffs[x], ringQ.N, nttPsi, qi, mredParams, bredParams)
		}
	}
	// c2QiP = c2 mod qi mod pj
	ringP.NTTLazy(c2QiP, c2QiP)
}

func (eval *mfvEvaluator) DecompInternal(c2InvNTT *ring.Poly, c2QiQDecomp, c2QiPDecomp []*ring.Poly) {
	level := c2InvNTT.Level()
	ringQ := eval.ringQ
	c2NTT := eval.poolQ[1][0]
	ringQ.NTTLvl(level, c2InvNTT, c2NTT)

	alpha := eval.params.Alpha()
	beta := int(math.Ceil(float64(level+1) / float64(alpha)))

	for i := 0; i < beta; i++ {
		eval.decomposeAndSplitNTT(level, i, c2NTT, c2InvNTT, c2QiQDecomp[i], c2QiPDecomp[i])
	}
}

func (eval *mfvEvaluator) rotateHoistedNoModDown(ct0 *Ciphertext, rotations []int, c2QiQDecomp, c2QiPDecomp []*ring.Poly) (cOutQ, cOutP map[int][2]*ring.Poly) {
	ringQ := eval.ringQ

	cOutQ = make(map[int][2]*ring.Poly)
	cOutP = make(map[int][2]*ring.Poly)

	level := ct0.Level()

	for _, i := range rotations {
		if i != 0 {
			cOutQ[i] = [2]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly()}
			cOutP[i] = [2]*ring.Poly{eval.params.NewPolyP(), eval.params.NewPolyP()}

			eval.permuteNTTHoistedNoModDown(level, c2QiQDecomp, c2QiPDecomp, i, cOutQ[i][0], cOutQ[i][1], cOutP[i][0], cOutP[i][1])
		}
	}

	return
}

func (eval *mfvEvaluator) permuteNTTHoistedNoModDown(level int, c2QiQDecomp, c2QiPDecomp []*ring.Poly, k int, ct0OutQ, ct1OutQ, ct0OutP, ct1OutP *ring.Poly) {
	if c2QiQDecomp[0].Level() != c2QiPDecomp[0].Level() {
		panic("cannot permuteNTTHoistedNoModDown: c2QiQDecomp and c2QiPDecomp should have the same level")
	}

	pool2Q := eval.poolQ[0][0]
	pool3Q := eval.poolQ[0][1]

	pool2P := eval.poolP[0]
	pool3P := eval.poolP[1]

	levelQ := level
	levelP := eval.params.PiCount() - 1

	galEl := eval.params.GaloisElementForColumnRotationBy(k)

	rtk, generated := eval.rtks.Keys[galEl]
	if !generated {
		fmt.Println(k)
		panic("switching key not available")
	}
	index := eval.permuteNTTIndex[galEl]

	eval.keyswitchHoistedNoModDown(levelQ, c2QiQDecomp, c2QiPDecomp, rtk, pool2Q, pool3Q, pool2P, pool3P)

	ring.PermuteNTTWithIndexLvl(levelQ, pool2Q, index, ct0OutQ)
	ring.PermuteNTTWithIndexLvl(levelQ, pool3Q, index, ct1OutQ)

	ring.PermuteNTTWithIndexLvl(levelP, pool2P, index, ct0OutP)
	ring.PermuteNTTWithIndexLvl(levelP, pool3P, index, ct1OutP)
}

func (eval *mfvEvaluator) keyswitchHoistedNoModDown(level int, c2QiQDecomp, c2QiPDecomp []*ring.Poly, evakey *rlwe.SwitchingKey, pool2Q, pool3Q, pool2P, pool3P *ring.Poly) {

	ringQ := eval.ringQ
	ringP := eval.ringP

	alpha := eval.params.Alpha()
	beta := int(math.Ceil(float64(level+1) / float64(alpha)))

	evakey0Q := new(ring.Poly)
	evakey1Q := new(ring.Poly)
	evakey0P := new(ring.Poly)
	evakey1P := new(ring.Poly)

	QiOverF := eval.params.QiOverflowMargin(level) >> 1
	PiOverF := eval.params.PiOverflowMargin() >> 1

	// Key switching with CRT decomposition for the Qi
	var reduce int
	for i := 0; i < beta; i++ {

		evakey0Q.Coeffs = evakey.Value[i][0].Coeffs[:level+1]
		evakey1Q.Coeffs = evakey.Value[i][1].Coeffs[:level+1]
		evakey0P.Coeffs = evakey.Value[i][0].Coeffs[len(ringQ.Modulus):]
		evakey1P.Coeffs = evakey.Value[i][1].Coeffs[len(ringQ.Modulus):]

		if i == 0 {
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey0Q, c2QiQDecomp[i], pool2Q)
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey1Q, c2QiQDecomp[i], pool3Q)
			ringP.MulCoeffsMontgomeryConstant(evakey0P, c2QiPDecomp[i], pool2P)
			ringP.MulCoeffsMontgomeryConstant(evakey1P, c2QiPDecomp[i], pool3P)
		} else {
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey0Q, c2QiQDecomp[i], pool2Q)
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey1Q, c2QiQDecomp[i], pool3Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey0P, c2QiPDecomp[i], pool2P)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey1P, c2QiPDecomp[i], pool3P)
		}

		if reduce%QiOverF == QiOverF-1 {
			ringQ.ReduceLvl(level, pool2Q, pool2Q)
			ringQ.ReduceLvl(level, pool3Q, pool3Q)
		}

		if reduce%PiOverF == PiOverF-1 {
			ringP.Reduce(pool2P, pool2P)
			ringP.Reduce(pool3P, pool3P)
		}

		reduce++
	}

	if reduce%QiOverF != 0 {
		ringQ.ReduceLvl(level, pool2Q, pool2Q)
		ringQ.ReduceLvl(level, pool3Q, pool3Q)
	}

	if reduce%PiOverF != 0 {
		ringP.Reduce(pool2P, pool2P)
		ringP.Reduce(pool3P, pool3P)
	}
}

func (eval *mfvEvaluator) SwitchKeysInPlaceNoModDown(level int, cx *ring.Poly, evakey *rlwe.SwitchingKey, pool2Q, pool2P, pool3Q, pool3P *ring.Poly) {
	var reduce int

	ringQ := eval.ringQ
	ringP := eval.ringP

	// Pointers allocation
	c2QiQ := eval.poolQ[0][0]
	c2QiP := eval.poolP[0]

	c2 := eval.poolQ[1][0]

	evakey0Q := new(ring.Poly)
	evakey1Q := new(ring.Poly)
	evakey0P := new(ring.Poly)
	evakey1P := new(ring.Poly)

	// We switch the element on which the switching key operation will be conducted out of the NTT domain

	ringQ.InvNTTLvl(level, cx, c2)

	reduce = 0

	alpha := eval.params.Alpha()
	beta := int(math.Ceil(float64(level+1) / float64(alpha)))

	QiOverF := eval.params.QiOverflowMargin(level) >> 1
	PiOverF := eval.params.PiOverflowMargin() >> 1

	// Key switching with CRT decomposition for the Qi
	for i := 0; i < beta; i++ {
		eval.decomposeAndSplitNTT(level, i, cx, c2, c2QiQ, c2QiP)

		evakey0Q.Coeffs = evakey.Value[i][0].Coeffs[:level+1]
		evakey1Q.Coeffs = evakey.Value[i][1].Coeffs[:level+1]
		evakey0P.Coeffs = evakey.Value[i][0].Coeffs[len(ringQ.Modulus):]
		evakey1P.Coeffs = evakey.Value[i][1].Coeffs[len(ringQ.Modulus):]

		if i == 0 {
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey0Q, c2QiQ, pool2Q)
			ringQ.MulCoeffsMontgomeryConstantLvl(level, evakey1Q, c2QiQ, pool3Q)
			ringP.MulCoeffsMontgomeryConstant(evakey0P, c2QiP, pool2P)
			ringP.MulCoeffsMontgomeryConstant(evakey1P, c2QiP, pool3P)
		} else {
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey0Q, c2QiQ, pool2Q)
			ringQ.MulCoeffsMontgomeryConstantAndAddNoModLvl(level, evakey1Q, c2QiQ, pool3Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey0P, c2QiP, pool2P)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(evakey1P, c2QiP, pool3P)
		}

		if reduce%QiOverF == QiOverF-1 {
			ringQ.ReduceLvl(level, pool2Q, pool2Q)
			ringQ.ReduceLvl(level, pool3Q, pool3Q)
		}

		if reduce%PiOverF == PiOverF-1 {
			ringP.Reduce(pool2P, pool2P)
			ringP.Reduce(pool3P, pool3P)
		}

		reduce++
	}

	if reduce%QiOverF != 0 {
		ringQ.ReduceLvl(level, pool2Q, pool2Q)
		ringQ.ReduceLvl(level, pool3Q, pool3Q)
	}

	if reduce%PiOverF != 0 {
		ringP.Reduce(pool2P, pool2P)
		ringP.Reduce(pool3P, pool3P)
	}
}

// ModSwitch switches modulus of ct0 one level down and returns the result in ctOut
func (eval *mfvEvaluator) ModSwitch(ct0 *Ciphertext, ctOut *Ciphertext) {
	level := ct0.Level()
	if level == 0 {
		panic("cannot ModSwitch: input has level zero")
	}

	if ct0.Degree() != ctOut.Degree() {
		panic("cannot ModSwitch: input and output should have the same degree")
	}

	ringQ := eval.ringQ
	for i := range ct0.value {
		ringQ.DivRoundByLastModulus(ct0.value[i], ctOut.value[i])
		ctOut.value[i].Coeffs = ctOut.value[i].Coeffs[:level]
	}
}

// ModSwitchMany switches modulus of ct0 nbModSwitch levels down and returns the result in ctOut
func (eval *mfvEvaluator) ModSwitchMany(ct0, ctOut *Ciphertext, nbModSwitch int) {
	if nbModSwitch <= 0 {
		panic("nbModSwitch should be a positive integer")
	}

	level := ct0.Level()
	if level < nbModSwitch {
		panic("cannot ModSwitchMany: input does not have enough levels")
	}

	if ct0.Degree() != ctOut.Degree() {
		panic("cannot ModSwitchMany: input and output should have the same degree")
	}

	ringQ := eval.ringQ
	for i := range ct0.value {
		ringQ.DivRoundByLastModulusMany(ct0.value[i], ctOut.value[i], nbModSwitch)
		ctOut.value[i].Coeffs = ctOut.value[i].Coeffs[:level+1-nbModSwitch]
	}
}

// TransformToNTT transforms ct0 into NTT form and returns the result in ctOut
func (eval *mfvEvaluator) TransformToNTT(ct0 *Ciphertext, ctOut *Ciphertext) {
	if ct0.Degree() != ctOut.Degree() {
		panic("cannot TransformToNTT: input and output must have the same degree")
	}

	if ct0.Level() != ctOut.Level() {
		panic("cannot TransformToNTT: input and output must have the same level")
	}

	level := ct0.Level()
	for i := range ct0.value {
		eval.ringQs[level].NTT(ct0.value[i], ctOut.value[i])
	}

	ctOut.SetIsNTT(true)
}

// SlotsToCoeffs returns ctOut whose coefficients are data stored in slots of ct
// with dropping modulus as given in stcModDown
func (eval *mfvEvaluator) SlotsToCoeffs(ct *Ciphertext, stcModDown []int) (ctOut *Ciphertext) {
	if eval.pDcds == nil {
		panic("cannot SlotsToCoeffs: evaluator does not have StC matrices")
	}

	ctOut = ct.CopyNew().Ciphertext()

	level := ctOut.Level()
	depth := len(eval.pDcds[level]) - 1
	for i := 0; i < depth-1; i++ {
		if stcModDown[i] > 0 {
			eval.ModSwitchMany(ctOut, ctOut, stcModDown[i])
		}
		level = ctOut.Level()
		ctOut = eval.LinearTransform(ctOut, eval.pDcds[level][i])[0]
	}
	if stcModDown[depth-1] > 0 {
		eval.ModSwitchMany(ctOut, ctOut, stcModDown[depth-1])
	}
	level = ctOut.Level()
	tmp := eval.RotateRowsNew(ctOut)
	ctOut = eval.LinearTransform(ctOut, eval.pDcds[level][depth-1])[0]
	tmp = eval.LinearTransform(tmp, eval.pDcds[level][depth])[0]

	ctOut = eval.AddNew(tmp, ctOut)
	return
}

// SlotsToCoeffsNoModSwitch returns ctOut whose coefficients are data stored in slots of ct
// without modulus switching
func (eval *mfvEvaluator) SlotsToCoeffsNoModSwitch(ct *Ciphertext) (ctOut *Ciphertext) {
	if eval.pDcds == nil {
		panic("cannot SlotsToCoeffs: evaluator does not have StC matrices")
	}

	ctOut = ct.CopyNew().Ciphertext()

	level := ct.Level()
	depth := len(eval.pDcds[level]) - 1
	for i := 0; i < depth-1; i++ {
		ctOut = eval.LinearTransform(ctOut, eval.pDcds[level][i])[0]
	}

	tmp := eval.RotateRowsNew(ctOut)
	ctOut = eval.LinearTransform(ctOut, eval.pDcds[level][depth-1])[0]
	tmp = eval.LinearTransform(tmp, eval.pDcds[level][depth])[0]

	ctOut = eval.AddNew(tmp, ctOut)
	return
}

func (eval *mfvEvaluator) findBudgetInfo(ct *Ciphertext, noiseEstimator MFVNoiseEstimator) (invBudget, errorBits int) {
	plainModulus := ring.NewUint(eval.params.PlainModulus())
	invBudget = noiseEstimator.InvariantNoiseBudget(ct)
	errorBits = eval.params.LogQLvl(ct.Level()) - plainModulus.BitLen() - invBudget
	return
}

func (eval *mfvEvaluator) modSwitchAuto(ct *Ciphertext, noiseEstimator MFVNoiseEstimator, depth int, stcModDown []int) {
	lvl := ct.Level()

	QiLvl := eval.params.Qi()[:lvl+1]
	LogQiLvl := make([]int, lvl+1)
	for i := 0; i < lvl+1; i++ {
		LogQiLvl[i] = int(math.Round(math.Log2(float64(QiLvl[i]))))
	}

	invBudgetOld, errorBitsOld := eval.findBudgetInfo(ct, noiseEstimator)
	nbModSwitch, targetErrorBits := 0, errorBitsOld
	for {
		targetErrorBits -= LogQiLvl[lvl-nbModSwitch]
		if targetErrorBits > 1 {
			nbModSwitch++
		} else {
			break
		}
	}

	if nbModSwitch != 0 {
		tmp := ct.CopyNew().Ciphertext()
		eval.ModSwitchMany(ct, ct, nbModSwitch)
		invBudgetNew, _ := eval.findBudgetInfo(tmp, noiseEstimator)

		if invBudgetOld-invBudgetNew > 3 {
			nbModSwitch--
		}
		ct = tmp
	}

	if nbModSwitch != 0 {
		stcModDown[depth] = nbModSwitch
		eval.ModSwitchMany(ct, ct, nbModSwitch)
		invBudgetNew, errorBitsNew := eval.findBudgetInfo(ct, noiseEstimator)
		fmt.Printf("StC Depth %d [Budget | Error] : [%v | %v] -> [%v | %v]\n", depth, invBudgetOld, errorBitsOld, invBudgetNew, errorBitsNew)
		fmt.Printf("StC modDown : %v\n\n", stcModDown)
	}
}

// SlotsToCoeffs returns ctOut whose coefficients are data stored in slots of ct
// with automatic modulus switching as written in stcModDown
func (eval *mfvEvaluator) SlotsToCoeffsAutoModSwitch(ct *Ciphertext, noiseEstimator MFVNoiseEstimator) (ctOut *Ciphertext, stcModDown []int) {
	if eval.pDcds == nil {
		panic("cannot SlotsToCoeffs: evaluator does not have StC matrices")
	}

	ctOut = ct.CopyNew().Ciphertext()
	level := ct.Level()
	depth := len(eval.pDcds[level]) - 1

	stcModDown = make([]int, depth)
	for i := 0; i < depth-1; i++ {
		eval.modSwitchAuto(ctOut, noiseEstimator, i, stcModDown)
		level = ctOut.Level()
		ctOut = eval.LinearTransform(ctOut, eval.pDcds[level][i])[0]
	}
	eval.modSwitchAuto(ctOut, noiseEstimator, depth-1, stcModDown)
	level = ctOut.Level()
	tmp := eval.RotateRowsNew(ctOut)
	ctOut = eval.LinearTransform(ctOut, eval.pDcds[level][depth-1])[0]
	tmp = eval.LinearTransform(tmp, eval.pDcds[level][depth])[0]

	ctOut = eval.AddNew(tmp, ctOut)
	invBudget, errorBits := eval.findBudgetInfo(ctOut, noiseEstimator)
	fmt.Printf("StC Final [Budget | Error] : [%v | %v]\n", invBudget, errorBits)
	fmt.Printf("StC modDown : %v\n\n", stcModDown)
	return
}
