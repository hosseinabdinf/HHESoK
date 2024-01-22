// Package bfv implements a RNS-accelerated Fan-Vercauteren version of Brakerski's scale invariant homomorphic encryption scheme. It provides modular arithmetic over the integers.
package ckks_fv

import (
	"fmt"
	"math/big"
	"unsafe"

	"HHESoK/ckks_integration/ring"
	"HHESoK/ckks_integration/utils"
)

// GaloisGen is an integer of order N=2^d modulo M=2N and that spans Z_M with the integer -1.
// The j-th ring automorphism takes the root zeta to zeta^(5j).
// const GaloisGen int = 5

// Encoder is an interface for plaintext encoding and decoding operations. It provides methods to embed []uint64 and []int64 types into
// the various plaintext types and the inverse operations. It also provides methodes to convert between the different plaintext types.
// The different plaintext types represent different embeddings of the message in the polynomial space. This relation is illustrated in
// The figure below:
//
// []uint64 --- Encoder.EncodeUintRingT(.) -┬-> PlaintextRingT -┬-> Encoder.ScaleUp(.) -----> Plaintext
// []uint64 --- Encoder.EncodeIntRingT(.) --┘                   └-> Encoder.RingTToMul(.) ---> PlaintextMul
//
// The different plaintext types have different efficiency-related caracteristics that we summarize in the Table below. For more information
// about the different plaintext types, see plaintext.go.
//
// Relative efficiency of operation
//
//	-----------------------------------------------------------------------
//
// |                      |  PlaintextRingT  |  Plaintext  | PlaintextMul  |
//
//	-----------------------------------------------------------------------
//
// | Encoding/Decoding    |    Faster      |    Slower   |    Slower       |
// | Memory size          |    Smaller     |    Larger   |    Larger       |
// | Ct-Pt Add / Sub      |    Slower      |    Faster   |    N/A          |
// | Ct-Pt Mul            |    Faster      |    Slower   |    Much Faster  |
//
//	-----------------------------------------------------------------------
type MFVEncoder interface {
	EncodeUint(coeffs []uint64, pt *Plaintext)
	EncodeUintRingT(coeffs []uint64, pt *PlaintextRingT)
	EncodeUintMul(coeffs []uint64, pt *PlaintextMul)
	EncodeInt(coeffs []int64, pt *Plaintext)
	EncodeIntRingT(coeffs []int64, pt *PlaintextRingT)
	EncodeIntMul(coeffs []int64, pt *PlaintextMul)

	FVScaleUp(*PlaintextRingT, *Plaintext)
	FVScaleDown(pt *Plaintext, ptRt *PlaintextRingT)
	RingTToMul(ptRt *PlaintextRingT, ptmul *PlaintextMul)
	MulToRingT(pt *PlaintextMul, ptRt *PlaintextRingT)

	DecodeRingT(pt interface{}, ptRt *PlaintextRingT)
	DecodeUint(pt interface{}, coeffs []uint64)
	DecodeInt(pt interface{}, coeffs []int64)
	DecodeUintNew(pt interface{}) (coeffs []uint64)
	DecodeIntNew(pt interface{}) (coeffs []int64)

	EncodeDiagMatrixT(level int, vector map[int][]uint64, maxM1N2Ratio float64, logSlots int) (matrix *PtDiagMatrixT)
	GenSlotToCoeffMatFV(radix int) (pDcds [][]*PtDiagMatrixT)

	EncodeUintRingTSmall(coeffs []uint64, pt *PlaintextRingT)
	EncodeUintMulSmall(coeffs []uint64, pt *PlaintextMul)
	EncodeUintSmall(coeffs []uint64, p *Plaintext)
	DecodeUintSmall(p interface{}, coeffs []uint64)
	DecodeUintSmallNew(p interface{}) (coeffs []uint64)
}

type multiLevelContext struct {
	maxLevel   int
	ringQs     []*ring.Ring
	scalers    []ring.Scaler
	deltasMont [][]uint64
}

// Encoder is a structure that stores the parameters to encode values on a plaintext in a SIMD (Single-Instruction Multiple-Data) fashion.
type mfvEncoder struct {
	params *Parameters

	ringP      *ring.Ring
	ringT      *ring.Ring
	ringTSmall *ring.Ring

	indexMatrix      []uint64
	indexMatrixSmall []uint64
	deltaPMont       []uint64
	multiLevelContext

	tmpPoly      *ring.Poly
	tmpPtRt      *PlaintextRingT
	tmpPolySmall *ring.Poly
}

func newMultiLevelContext(params *Parameters) multiLevelContext {
	var err error
	modCount := len(params.qi)
	ringQs := make([]*ring.Ring, modCount)
	scalers := make([]ring.Scaler, modCount)
	deltasMont := make([][]uint64, modCount)

	for i := 0; i < modCount; i++ {
		var ringQi *ring.Ring
		if ringQi, err = ring.NewRing(params.N(), params.qi[:i+1]); err != nil {
			panic(err)
		}
		ringQs[i] = ringQi
		deltasMont[i] = GenLiftParams(ringQi, params.plainModulus)
		scalers[i] = ring.NewRNSScaler(params.plainModulus, ringQi)
	}

	return multiLevelContext{
		maxLevel:   modCount - 1,
		ringQs:     ringQs,
		scalers:    scalers,
		deltasMont: deltasMont,
	}
}

// NewMFVEncoder creates a new encoder from the provided parameters.
func NewMFVEncoder(params *Parameters) MFVEncoder {

	var ringP, ringT, ringTSmall *ring.Ring
	var err error

	context := newMultiLevelContext(params)

	if ringP, err = ring.NewRing(params.N(), params.pi); err != nil {
		panic(err)
	}

	if ringT, err = ring.NewRing(params.N(), []uint64{params.plainModulus}); err != nil {
		panic(err)
	}

	if ringTSmall, err = ring.NewRing(params.FVSlots(), []uint64{params.plainModulus}); err != nil {
		panic(err)
	}

	var m, pos, index1, index2 int

	slots := params.N()

	indexMatrix := make([]uint64, slots)

	logN := params.LogN()

	rowSize := params.N() >> 1
	m = (params.N() << 1)
	pos = 1

	for i := 0; i < rowSize; i++ {

		index1 = (pos - 1) >> 1
		index2 = (m - pos - 1) >> 1

		indexMatrix[i] = utils.BitReverse64(uint64(index1), uint64(logN))
		indexMatrix[i|rowSize] = utils.BitReverse64(uint64(index2), uint64(logN))

		pos *= GaloisGen
		pos &= (m - 1)
	}

	m = 2 * params.FVSlots()
	indexMatrixSmall := make([]uint64, params.FVSlots())
	logFVSlots := params.logFVSlots
	rowSize = params.FVSlots() >> 1
	pos = 1
	for i := 0; i < rowSize; i++ {
		index1 = (pos - 1) >> 1
		index2 = (m - pos - 1) >> 1

		indexMatrixSmall[i] = utils.BitReverse64(uint64(index1), uint64(logFVSlots))
		indexMatrixSmall[i|rowSize] = utils.BitReverse64(uint64(index2), uint64(logFVSlots))

		pos *= GaloisGen
		pos &= (m - 1)
	}

	return &mfvEncoder{
		params:            params.Copy(),
		ringP:             ringP,
		ringT:             ringT,
		ringTSmall:        ringTSmall,
		indexMatrix:       indexMatrix,
		indexMatrixSmall:  indexMatrixSmall,
		deltaPMont:        GenLiftParams(ringP, params.plainModulus),
		multiLevelContext: context,
		tmpPoly:           ringT.NewPoly(),
		tmpPtRt:           NewPlaintextRingT(params),
		tmpPolySmall:      ringTSmall.NewPoly(),
	}
}

// GenLiftParams generates the lifting parameters.
func GenLiftParams(ringQ *ring.Ring, plainModulus uint64) (deltaMont []uint64) {

	delta := new(big.Int).Quo(ringQ.ModulusBigint, ring.NewUint(plainModulus))

	deltaMont = make([]uint64, len(ringQ.Modulus))

	tmp := new(big.Int)
	bredParams := ringQ.BredParams
	for i, Qi := range ringQ.Modulus {
		deltaMont[i] = tmp.Mod(delta, ring.NewUint(Qi)).Uint64()
		deltaMont[i] = ring.MForm(deltaMont[i], Qi, bredParams[i])
	}

	return
}

// EncodeUintRingT encodes a slice of uint64 into a Plaintext in R_t
func (encoder *mfvEncoder) EncodeUintRingT(coeffs []uint64, p *PlaintextRingT) {
	if len(coeffs) > len(encoder.indexMatrix) {
		panic("invalid input to encode: number of coefficients must be smaller or equal to the ring degree")
	}

	if len(p.value.Coeffs[0]) != len(encoder.indexMatrix) {
		panic("invalid plaintext to receive encoding: number of coefficients does not match the ring degree")
	}

	for i := 0; i < len(coeffs); i++ {
		p.value.Coeffs[0][encoder.indexMatrix[i]] = coeffs[i]
	}

	for i := len(coeffs); i < len(encoder.indexMatrix); i++ {
		p.value.Coeffs[0][encoder.indexMatrix[i]] = coeffs[i%len(coeffs)]
	}

	encoder.ringT.InvNTT(p.value, p.value)
}

// EncodeUintRingTSmall encodes a slice of uint64 of length FVSlots into a Plaintext R_t
func (encoder *mfvEncoder) EncodeUintRingTSmall(coeffs []uint64, p *PlaintextRingT) {
	if len(coeffs) != len(encoder.indexMatrixSmall) {
		panic("invalid input to encode: number of coefficients must be equal to the number of FV slots")
	}

	if len(p.value.Coeffs[0]) != len(encoder.indexMatrix) {
		panic("invalid plaintext to receive encoding: number of coefficients does not match the ring degree")
	}

	poly := encoder.tmpPolySmall
	for i := 0; i < len(coeffs); i++ {
		poly.Coeffs[0][encoder.indexMatrixSmall[i]] = coeffs[i]
	}
	encoder.ringTSmall.InvNTT(poly, poly)

	gap := 1 << (encoder.params.logN - encoder.params.logFVSlots)
	for i := 0; i < len(coeffs); i++ {
		p.value.Coeffs[0][i*gap] = poly.Coeffs[0][i]
	}
}

// EncodeUint encodes an uint64 slice of size at most N on a plaintext.
func (encoder *mfvEncoder) EncodeUint(coeffs []uint64, p *Plaintext) {
	ptRt := &PlaintextRingT{p.Element, p.Element.value[0]}

	// Encodes the values in RingT
	encoder.EncodeUintRingT(coeffs, ptRt)

	// Scales by Q/t
	encoder.FVScaleUp(ptRt, p)
}

// EncodeUintSmall encodes an uint64 slice of size FVSlots on a plaintext
func (encoder *mfvEncoder) EncodeUintSmall(coeffs []uint64, p *Plaintext) {
	ptRt := &PlaintextRingT{p.Element, p.Element.value[0]}

	encoder.EncodeUintRingTSmall(coeffs, ptRt)

	encoder.FVScaleUp(ptRt, p)
}

func (encoder *mfvEncoder) EncodeUintMul(coeffs []uint64, p *PlaintextMul) {

	ptRt := &PlaintextRingT{p.Element, p.Element.value[0]}

	// Encodes the values in RingT
	encoder.EncodeUintRingT(coeffs, ptRt)

	// Puts in NTT+Montgomery domains of ringQ
	encoder.RingTToMul(ptRt, p)
}

func (encoder *mfvEncoder) EncodeUintMulSmall(coeffs []uint64, p *PlaintextMul) {
	ptRt := &PlaintextRingT{p.Element, p.Element.value[0]}

	encoder.EncodeUintRingTSmall(coeffs, ptRt)

	encoder.RingTToMul(ptRt, p)
}

// EncodeInt encodes an int64 slice of size at most N on a plaintext. It also encodes the sign of the given integer (as its inverse modulo the plaintext modulus).
// The sign will correctly decode as long as the absolute value of the coefficient does not exceed half of the plaintext modulus.
func (encoder *mfvEncoder) EncodeIntRingT(coeffs []int64, p *PlaintextRingT) {

	if len(coeffs) > len(encoder.indexMatrix) {
		panic("invalid input to encode: number of coefficients must be smaller or equal to the ring degree")
	}

	if len(p.value.Coeffs[0]) != len(encoder.indexMatrix) {
		panic("invalid plaintext to receive encoding: number of coefficients does not match the ring degree")
	}

	for i := 0; i < len(coeffs); i++ {

		if coeffs[i] < 0 {
			p.value.Coeffs[0][encoder.indexMatrix[i]] = uint64(int64(encoder.params.plainModulus) + coeffs[i])
		} else {
			p.value.Coeffs[0][encoder.indexMatrix[i]] = uint64(coeffs[i])
		}
	}

	for i := len(coeffs); i < len(encoder.indexMatrix); i++ {
		p.value.Coeffs[0][encoder.indexMatrix[i]] = 0
	}

	encoder.ringT.InvNTTLazy(p.value, p.value)
}

func (encoder *mfvEncoder) EncodeInt(coeffs []int64, p *Plaintext) {
	ptRt := &PlaintextRingT{p.Element, p.value}

	// Encodes the values in RingT
	encoder.EncodeIntRingT(coeffs, ptRt)

	// Scales by Q/t
	encoder.FVScaleUp(ptRt, p)
}

func (encoder *mfvEncoder) EncodeIntMul(coeffs []int64, p *PlaintextMul) {
	ptRt := &PlaintextRingT{p.Element, p.value}

	// Encodes the values in RingT
	encoder.EncodeIntRingT(coeffs, ptRt)

	// Puts in NTT+Montgomery domains of ringQ
	encoder.RingTToMul(ptRt, p)
}

// FVScaleUp transforms a PlaintextRingT (R_t) into a Plaintext (R_q) by scaling up the coefficient by Q/t.
func (encoder *mfvEncoder) FVScaleUp(ptRt *PlaintextRingT, pt *Plaintext) {
	level := pt.Level()
	ringQ := encoder.ringQs[level]
	deltaMont := encoder.deltasMont[level]
	fvScaleUp(ringQ, deltaMont, ptRt.value, pt.value)
}

func fvScaleUp(ringQ *ring.Ring, deltaMont []uint64, pIn, pOut *ring.Poly) {

	for i := len(ringQ.Modulus) - 1; i >= 0; i-- {
		out := pOut.Coeffs[i]
		in := pIn.Coeffs[0]
		d := deltaMont[i]
		qi := ringQ.Modulus[i]
		mredParams := ringQ.MredParams[i]

		for j := 0; j < ringQ.N; j = j + 8 {

			x := (*[8]uint64)(unsafe.Pointer(&in[j]))
			z := (*[8]uint64)(unsafe.Pointer(&out[j]))

			z[0] = ring.MRed(x[0], d, qi, mredParams)
			z[1] = ring.MRed(x[1], d, qi, mredParams)
			z[2] = ring.MRed(x[2], d, qi, mredParams)
			z[3] = ring.MRed(x[3], d, qi, mredParams)
			z[4] = ring.MRed(x[4], d, qi, mredParams)
			z[5] = ring.MRed(x[5], d, qi, mredParams)
			z[6] = ring.MRed(x[6], d, qi, mredParams)
			z[7] = ring.MRed(x[7], d, qi, mredParams)
		}
	}
}

// FVScaleDown transforms a Plaintext (R_q) into a PlaintextRingT (R_t) by scaling down the coefficient by t/Q and rounding.
func (encoder *mfvEncoder) FVScaleDown(pt *Plaintext, ptRt *PlaintextRingT) {
	level := pt.Level()
	encoder.scalers[level].DivByQOverTRounded(pt.value, ptRt.value)
}

// RingTToMul transforms a PlaintextRingT into a PlaintextMul by operating the NTT transform
// of R_q and putting the coefficients in Montgomery form.
func (encoder *mfvEncoder) RingTToMul(ptRt *PlaintextRingT, ptMul *PlaintextMul) {
	if ptRt.value != ptMul.value {
		copy(ptMul.value.Coeffs[0], ptRt.value.Coeffs[0])
	}

	level := ptMul.Level()
	for i := 1; i < level+1; i++ {
		copy(ptMul.value.Coeffs[i], ptRt.value.Coeffs[0])
	}

	ringQ := encoder.ringQs[level]
	ringQ.NTTLazy(ptMul.value, ptMul.value)
	ringQ.MForm(ptMul.value, ptMul.value)
}

// MulToRingT transforms a PlaintextMul into PlaintextRingT by operating the inverse NTT transform of R_q and
// putting the coefficients out of the Montgomery form.
func (encoder *mfvEncoder) MulToRingT(pt *PlaintextMul, ptRt *PlaintextRingT) {
	level := pt.Level()
	ringQ := encoder.ringQs[level]
	ringQ.InvNTTLvl(0, pt.value, ptRt.value)
	ringQ.InvMFormLvl(0, ptRt.value, ptRt.value)
}

// DecodeRingT decodes any plaintext type into a PlaintextRingT. It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeRingT(p interface{}, ptRt *PlaintextRingT) {
	switch pt := p.(type) {
	case *Plaintext:
		encoder.FVScaleDown(pt, ptRt)
	case *PlaintextMul:
		encoder.MulToRingT(pt, ptRt)
	case *PlaintextRingT:
		ptRt.Copy(pt.Element)
	default:
		panic(fmt.Errorf("unsupported plaintext type (%T)", pt))
	}
}

// DecodeUint decodes a any plaintext type and write the coefficients in coeffs. It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeUint(p interface{}, coeffs []uint64) {

	var ptRt *PlaintextRingT
	var isInRingT bool
	if ptRt, isInRingT = p.(*PlaintextRingT); !isInRingT {
		encoder.DecodeRingT(p, encoder.tmpPtRt)
		ptRt = encoder.tmpPtRt
	}

	encoder.ringT.NTT(ptRt.value, encoder.tmpPoly)

	for i := 0; i < encoder.params.N(); i++ {
		coeffs[i] = encoder.tmpPoly.Coeffs[0][encoder.indexMatrix[i]]
	}
}

// DecodeUintSmallNew decodes any plaintext type and returns the coefficients in a new []uint64.
// It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeUintSmallNew(p interface{}) (coeffs []uint64) {
	coeffs = make([]uint64, encoder.params.FVSlots())
	encoder.DecodeUintSmall(p, coeffs)
	return
}

// DecodeUintSmall decodes any plaintext type and write the coefficients in coeffs. It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeUintSmall(p interface{}, coeffs []uint64) {
	var ptRt *PlaintextRingT
	var isInRingT bool
	if ptRt, isInRingT = p.(*PlaintextRingT); !isInRingT {
		encoder.DecodeRingT(p, encoder.tmpPtRt)
		ptRt = encoder.tmpPtRt
	}

	poly := encoder.tmpPolySmall
	gap := 1 << (encoder.params.logN - encoder.params.logFVSlots)
	for i := 0; i < encoder.params.FVSlots(); i++ {
		poly.Coeffs[0][i] = ptRt.value.Coeffs[0][i*gap]
	}

	encoder.ringTSmall.NTT(poly, poly)

	for i := 0; i < encoder.params.FVSlots(); i++ {
		coeffs[i] = poly.Coeffs[0][encoder.indexMatrixSmall[i]]
	}
}

// DecodeUintNew decodes any plaintext type and returns the coefficients in a new []uint64.
// It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeUintNew(p interface{}) (coeffs []uint64) {
	coeffs = make([]uint64, encoder.params.N())
	encoder.DecodeUint(p, coeffs)
	return
}

// DecodeInt decodes a any plaintext type and write the coefficients in coeffs. It also decodes the sign
// modulus (by centering the values around the plaintext). It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeInt(p interface{}, coeffs []int64) {

	encoder.DecodeRingT(p, encoder.tmpPtRt)

	encoder.ringT.NTT(encoder.tmpPtRt.value, encoder.tmpPoly)

	modulus := int64(encoder.params.plainModulus)
	modulusHalf := modulus >> 1
	var value int64
	for i := 0; i < encoder.params.N(); i++ {

		value = int64(encoder.tmpPoly.Coeffs[0][encoder.indexMatrix[i]])
		coeffs[i] = value
		if value >= modulusHalf {
			coeffs[i] -= modulus
		}
	}
}

// DecodeIntNew decodes any plaintext type and returns the coefficients in a new []int64. It also decodes the sign
// modulus (by centering the values around the plaintext). It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeIntNew(p interface{}) (coeffs []int64) {
	coeffs = make([]int64, encoder.params.N())
	encoder.DecodeInt(p, coeffs)
	return
}

// PtDiagMatrixT is a struct storing a plaintext diagonalized matrix
// ready to be evaluated on a ciphertext using evaluator.MultiplyByDiagMatrice.
type PtDiagMatrixT struct {
	LogFVSlots int                   // Log of the number of slots of the plaintext
	N1         int                   // N1 is the number of inner loops of the baby-step giant-step algo used in the evaluation
	Vec        map[int][2]*ring.Poly // Vec is the matrix, in diagonal form, where each entry of vec is an indexed non zero diagonal
	naive      bool
}

// EncodeDiagMatrixT encodes a diagonalized plaintext matrix into PtDiagMatrixT struct.
// It can then be evaluated on a ciphertext using evaluator.MultiplyByDiagMatrice.
// maxN1N2Ratio is the maximum ratio between the inner and outer loop of the baby-step giant-step algorithm used in evaluator.MultiplyByDiagMatrice.
// Optimal maxN1N2Ratio value is between 4 and 16 depending on the sparsity of the matrix.
func (encoder *mfvEncoder) EncodeDiagMatrixT(level int, diagMatrix map[int][]uint64, maxN1N2Ratio float64, logFVSlots int) (matrix *PtDiagMatrixT) {
	matrix = new(PtDiagMatrixT)
	matrix.LogFVSlots = logFVSlots
	fvSlots := 1 << logFVSlots

	if len(diagMatrix) > 2 {
		// N1*N2 = N
		N1 := findbestbabygiantstepsplit(diagMatrix, fvSlots, maxN1N2Ratio)
		matrix.N1 = N1

		index, _ := bsgsIndex(diagMatrix, fvSlots, N1)

		matrix.Vec = make(map[int][2]*ring.Poly)

		for j := range index {
			for _, i := range index[j] {
				// manages inputs that have rotation between 0 and slots-1 or between -slots/2 and slots/2-1
				v := diagMatrix[N1*j+i]
				if len(v) == 0 {
					v = diagMatrix[(N1*j+i)-fvSlots]
				}

				matrix.Vec[N1*j+i] = encoder.encodeDiagonalT(level, logFVSlots, rotateSmallT(v, -N1*j))
			}
		}
	} else {
		matrix.Vec = make(map[int][2]*ring.Poly)

		for i := range diagMatrix {
			idx := i
			if idx < 0 {
				idx += fvSlots
			}
			matrix.Vec[idx] = encoder.encodeDiagonalT(level, logFVSlots, diagMatrix[i])
		}

		matrix.naive = true
	}

	return
}

func (encoder *mfvEncoder) encodeDiagonalT(level, logFVSlots int, m []uint64) [2]*ring.Poly {
	ringQ := encoder.ringQs[level]
	ringP := encoder.ringP
	ringT := encoder.ringT
	ringTSmall := encoder.ringTSmall
	tmp := encoder.tmpPolySmall

	// EncodeUintRingT
	for i := 0; i < len(m); i++ {
		tmp.Coeffs[0][encoder.indexMatrixSmall[i]] = m[i]
	}
	ringTSmall.InvNTT(tmp, tmp)

	mT := ringT.NewPoly()
	gap := 1 << (encoder.params.logN - logFVSlots)
	for i := 0; i < (1 << logFVSlots); i++ {
		mT.Coeffs[0][i*gap] = tmp.Coeffs[0][i]
	}

	// RingTToMulRingQ
	mQ := ringQ.NewPoly()
	for i := 0; i < len(ringQ.Modulus); i++ {
		copy(mQ.Coeffs[i], mT.Coeffs[0])
	}
	ringQ.NTTLazy(mQ, mQ)
	ringQ.MForm(mQ, mQ)

	// RingTToMulRingP
	mP := ringP.NewPoly()
	for i := 0; i < len(encoder.ringP.Modulus); i++ {
		copy(mP.Coeffs[i], mT.Coeffs[0])
	}
	ringP.NTTLazy(mP, mP)
	ringP.MForm(mP, mP)

	return [2]*ring.Poly{mQ, mP}
}

// GenSlotToCoeffMatFV generates the factorized decoding matrix for FV scheme.
// The decoding matrix is factorized into sparse block diagonal matrices with the given radix.
// radix 0 - decoding matrix is mergeed into one
// radix 1 - decoding matrix is factorized factorized with radix 1
// radix 2 - decoding matrix is factorized with radix 2
// other values are treated as radix 1
func (encoder *mfvEncoder) GenSlotToCoeffMatFV(radix int) (pDcds [][]*PtDiagMatrixT) {
	params := encoder.params

	modCount := len(params.qi)
	pDcds = make([][]*PtDiagMatrixT, modCount)

	var genDcdFunc func(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64)
	switch radix {
	case 0:
		genDcdFunc = genDcdMatsInOne
	case 2:
		genDcdFunc = genDcdMatsRad2
	default:
		genDcdFunc = genDcdMats
	}
	for level := 0; level < modCount; level++ {
		pVecDcd := genDcdFunc(params.logFVSlots, params.plainModulus)
		pDcds[level] = make([]*PtDiagMatrixT, len(pVecDcd))

		for i := 0; i < len(pDcds[level]); i++ {
			pDcds[level][i] = encoder.EncodeDiagMatrixT(level, pVecDcd[i], 16.0, params.logFVSlots)
		}
	}

	return
}

// genDcdMats generates decoding matrix that is factorized into sparse block diagonal matrices with radix 1
func genDcdMats(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64) {
	roots := computePrimitiveRoots(1<<(logSlots+1), plainModulus)
	diabMats := genDcdDiabDecomp(logSlots, roots)
	depth := len(diabMats) - 1

	plainVector = make([]map[int][]uint64, depth)
	for i := 0; i < depth-2; i++ {
		plainVector[i] = diabMats[i]
	}
	plainVector[depth-2] = multDiabMats(diabMats[depth-1], diabMats[depth-2], plainModulus)
	plainVector[depth-1] = multDiabMats(diabMats[depth], diabMats[depth-2], plainModulus)
	return
}

// genDcdMatsRad2 generates decoding matrix that is factorized into sparse block diagonal matrices with radix 2
func genDcdMatsRad2(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64) {
	roots := computePrimitiveRoots(1<<(logSlots+1), plainModulus)
	diabMats := genDcdDiabDecomp(logSlots, roots)
	depth := len(diabMats) - 1

	plainVector = make([]map[int][]uint64, (depth+1)/2+1)
	if depth%2 == 0 {
		for i := 0; i < depth-2; i += 2 {
			plainVector[i/2] = multDiabMats(diabMats[i+1], diabMats[i], plainModulus)
		}
	} else {
		plainVector[0] = diabMats[0]
		for i := 1; i < depth-2; i += 2 {
			plainVector[(i+1)/2] = multDiabMats(diabMats[i+1], diabMats[i], plainModulus)
		}
	}
	plainVector[(depth-1)/2] = multDiabMats(diabMats[depth-1], diabMats[depth-2], plainModulus)
	plainVector[(depth+1)/2] = multDiabMats(diabMats[depth], diabMats[depth-2], plainModulus)
	return
}

// genDcdMatsInOne generates decoding matrix which is not factorized
func genDcdMatsInOne(logSlots int, plainModulus uint64) (plainVector []map[int][]uint64) {
	if logSlots != 4 {
		panic("cannot genDcdMatsInOne: logSlots should be 4")
	}
	roots := computePrimitiveRoots(1<<(logSlots+1), plainModulus)
	diabMats := genDcdDiabDecomp(logSlots, roots)

	plainVector = make([]map[int][]uint64, 2)
	tmp := diabMats[0]
	tmp = multDiabMats(diabMats[1], tmp, plainModulus)
	plainVector[0] = multDiabMats(diabMats[2], tmp, plainModulus)
	plainVector[1] = multDiabMats(diabMats[3], tmp, plainModulus)
	return
}

func multDiabMats(A map[int][]uint64, B map[int][]uint64, plainModulus uint64) (res map[int][]uint64) {
	res = make(map[int][]uint64)

	for rotA := range A {
		for rotB := range B {
			N := len(A[rotA])
			if res[(rotA+rotB)%(N/2)] == nil {
				res[(rotA+rotB)%(N/2)] = make([]uint64, N)
			}

			for i := 0; i < N/2; i++ {
				res[(rotA+rotB)%(N/2)][i] += A[rotA][i] * B[rotB][(rotA+i)%(N/2)]
				res[(rotA+rotB)%(N/2)][i] %= plainModulus

			}

			for i := N / 2; i < N; i++ {
				res[(rotA+rotB)%(N/2)][i] += A[rotA][i] * B[rotB][N/2+(rotA+i)%(N/2)]
				res[(rotA+rotB)%(N/2)][i] %= plainModulus
			}
		}
	}
	return
}

func genDcdDiabDecomp(logN int, roots []uint64) (res []map[int][]uint64) {
	N := 1 << logN
	M := 2 * N
	pow5 := make([]int, M)
	res = make([]map[int][]uint64, logN)

	for i, exp5 := 0, 1; i < N; i, exp5 = i+1, exp5*5%M {
		pow5[i] = exp5
	}
	res[0] = make(map[int][]uint64)
	res[0][0] = make([]uint64, N)
	res[0][1] = make([]uint64, N)
	res[0][2] = make([]uint64, N)
	res[0][3] = make([]uint64, N)
	res[0][N/2-1] = make([]uint64, N)
	res[0][N/2-2] = make([]uint64, N)
	res[0][N/2-3] = make([]uint64, N)
	for i := 0; i < N; i += 4 {
		res[0][0][i] = 1
		res[0][0][i+1] = roots[2*N/4]
		res[0][0][i+2] = roots[7*N/4]
		res[0][0][i+3] = roots[1*N/4]

		res[0][1][i] = roots[2*N/4]
		res[0][1][i+1] = roots[5*N/4]
		res[0][1][i+2] = roots[5*N/4]

		res[0][2][i] = roots[1*N/4]
		res[0][2][i+1] = roots[7*N/4]

		res[0][3][i] = roots[3*N/4]

		res[0][N/2-1][i+1] = 1
		res[0][N/2-1][i+2] = roots[6*N/4]
		res[0][N/2-1][i+3] = roots[3*N/4]

		res[0][N/2-2][i+2] = 1
		res[0][N/2-2][i+3] = roots[6*N/4]

		res[0][N/2-3][i+3] = 1
	}

	for ind := 1; ind < logN-2; ind++ {
		s := 1 << ind // size of each diabMat
		gap := N / s / 4

		res[ind] = make(map[int][]uint64)
		for _, rot := range []int{0, s, 2 * s, N/2 - s, N/2 - 2*s} {
			if res[ind][rot] == nil {
				res[ind][rot] = make([]uint64, N)
			}
		}

		for i := 0; i < N; i += 4 * s {
			/*
				[I 0 W0 0 ]
				[I 0 W1 0 ]
				[0 I 0 W0-]
				[0 I 0 W1-]
			*/
			for j := 0; j < s; j++ {
				res[ind][2*s][i+j] = roots[pow5[j]*gap%M]     // W0
				res[ind][s][i+s+j] = roots[pow5[s+j]*gap%M]   // W1
				res[ind][s][i+2*s+j] = roots[M-pow5[j]*gap%M] // W0-
				res[ind][0][i+j] = 1
				res[ind][0][i+3*s+j] = roots[M-pow5[s+j]*gap%M] // W1-
				res[ind][N/2-s][i+s+j] = 1
				res[ind][N/2-s][i+2*s+j] = 1
				res[ind][N/2-2*s][i+3*s+j] = 1
			}
		}
	}

	s := N / 4

	res[logN-2] = make(map[int][]uint64)
	res[logN-2][0] = make([]uint64, N)
	res[logN-2][s] = make([]uint64, N)

	res[logN-1] = make(map[int][]uint64)
	res[logN-1][0] = make([]uint64, N)
	res[logN-1][s] = make([]uint64, N)

	for i := 0; i < s; i++ {
		res[logN-2][0][i] = 1
		res[logN-2][0][i+3*s] = roots[M-pow5[s+i]%M]
		res[logN-2][s][i+s] = 1
		res[logN-2][s][i+2*s] = roots[M-pow5[i]%M]

		res[logN-1][0][i] = roots[pow5[i]%M]
		res[logN-1][0][i+3*s] = 1
		res[logN-1][s][i+s] = roots[pow5[s+i]%M]
		res[logN-1][s][i+2*s] = 1
	}
	return
}

// compute M-th root of unity
func computePrimitiveRoots(M int, plainModulus uint64) (roots []uint64) {
	g := ring.PrimitiveRoot(plainModulus)
	w := ring.ModExp(g, (int(plainModulus)-1)/M, plainModulus)

	roots = make([]uint64, M)
	roots[0] = 1
	for i := 1; i < M; i++ {
		roots[i] = (roots[i-1] * w) % plainModulus
	}
	return
}
