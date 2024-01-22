package ckks_fv

import (
	"math"
	"math/big"

	"HHESoK/ckks_integration/ring"
)

type MFVNoiseEstimator interface {
	InvariantNoiseBudget(ciphertext *Ciphertext) int
}

type mfvNoiseEstimator struct {
	params       *Parameters
	sk           *SecretKey
	ringQs       []*ring.Ring
	plainModulus uint64
	qHalfs       []*big.Int // (q+1)/2

	qib   [][]uint64   // (Q/Qi)^-1 (mod each Qi)
	qispj [][]*big.Int // Q/Qi (mod Q)

	polypool1  *ring.Poly
	polypool2  *ring.Poly
	coeffspool []*big.Int
	bigintpool [4]*big.Int
}

func NewMFVNoiseEstimator(params *Parameters, sk *SecretKey) MFVNoiseEstimator {

	var err error

	Q := params.qi
	modCount := len(Q)
	ringQs := make([]*ring.Ring, modCount)
	for i := range ringQs {
		if ringQs[i], err = ring.NewRing(params.N(), params.qi[:i+1]); err != nil {
			panic(err)
		}
	}

	QjB := new(big.Int)
	QjStar := new(big.Int)
	QjBarre := new(big.Int)

	qHalfs := make([]*big.Int, modCount)
	qib := make([][]uint64, modCount)
	qispj := make([][]*big.Int, modCount)

	for i := 0; i < modCount; i++ {
		qHalfs[i] = new(big.Int)
		qHalfs[i].Set(ringQs[i].ModulusBigint)
		qHalfs[i].Add(qHalfs[i], new(big.Int).SetUint64(1))
		qHalfs[i].Rsh(qHalfs[i], 1)

		qib[i] = make([]uint64, i+1)
		qispj[i] = make([]*big.Int, i+1)
		for j := 0; j <= i; j++ {
			qj := Q[j]
			QjB.SetUint64(qj)
			QjStar.Quo(ringQs[i].ModulusBigint, QjB)
			QjBarre.ModInverse(QjStar, QjB)
			QjBarre.Mod(QjBarre, QjB)

			qib[i][j] = QjBarre.Uint64()
			qispj[i][j] = new(big.Int).Set(QjStar)
		}
	}

	polypool1 := ringQs[modCount-1].NewPoly()
	polypool2 := ringQs[modCount-1].NewPoly()

	coeffspool := make([]*big.Int, params.N())
	for i := range coeffspool {
		coeffspool[i] = new(big.Int).SetUint64(0)
	}
	bigintpool := [4]*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}

	return &mfvNoiseEstimator{
		params:       params.Copy(),
		sk:           sk,
		ringQs:       ringQs,
		plainModulus: params.PlainModulus(),
		qHalfs:       qHalfs,

		qib:   qib,
		qispj: qispj,

		polypool1:  polypool1,
		polypool2:  polypool2,
		coeffspool: coeffspool,
		bigintpool: bigintpool,
	}
}

func (mfvNoiseEstimator *mfvNoiseEstimator) InvariantNoiseBudget(ciphertext *Ciphertext) int {

	if ciphertext.Degree() != 1 {
		panic("Ciphertext degree should be 1")
	}

	N := mfvNoiseEstimator.params.N()
	level := ciphertext.Level()
	ringQ := mfvNoiseEstimator.ringQs[level]
	Q := ringQ.Modulus
	modulusbigint := ringQ.ModulusBigint

	tmp := mfvNoiseEstimator.polypool1
	pool0Q := mfvNoiseEstimator.polypool2
	coeffspool := mfvNoiseEstimator.coeffspool

	tmpInt0 := mfvNoiseEstimator.bigintpool[0]
	tmpInt1 := mfvNoiseEstimator.bigintpool[1]
	tmpIntQi := mfvNoiseEstimator.bigintpool[2]
	norm := mfvNoiseEstimator.bigintpool[3]

	// Step 1. Dot product with the secret key
	ringQ.NTTLazy(ciphertext.value[1], pool0Q)
	ringQ.MulCoeffsMontgomery(pool0Q, mfvNoiseEstimator.sk.Value, pool0Q)
	ringQ.NTTLazy(ciphertext.value[0], tmp)
	ringQ.Add(pool0Q, tmp, pool0Q)

	ringQ.Reduce(pool0Q, pool0Q)
	ringQ.InvNTT(pool0Q, pool0Q)

	// Step 2. Multiply by t
	ringQ.MulScalar(pool0Q, mfvNoiseEstimator.plainModulus, pool0Q)

	// Step 3. CRT compose
	for i := 0; i < N; i++ {
		coeffspool[i].SetUint64(0)
		for j := 0; j <= level; j++ {
			tmpIntQi.SetUint64(Q[j])
			tmpInt0.SetUint64(pool0Q.Coeffs[j][i])
			tmpInt1.SetUint64(mfvNoiseEstimator.qib[level][j])
			tmpInt0.Mul(tmpInt0, tmpInt1)
			tmpInt0.Mod(tmpInt0, tmpIntQi)

			tmpInt0.Mul(tmpInt0, mfvNoiseEstimator.qispj[level][j])
			coeffspool[i].Add(coeffspool[i], tmpInt0)
			coeffspool[i].Mod(coeffspool[i], modulusbigint)
		}
	}

	// Step 4. Compute the infinity norm
	norm.SetUint64(0)
	qHalf := mfvNoiseEstimator.qHalfs[level]
	for i := 0; i < N; i++ {
		if coeffspool[i].Cmp(qHalf) >= 0 {
			coeffspool[i].Sub(modulusbigint, coeffspool[i])
		}

		if norm.Cmp(coeffspool[i]) < 0 {
			norm.Set(coeffspool[i])
		}
	}

	// Step 5. Compute noise budget
	bitCountDiff := getSignificantBitsCount(modulusbigint) - getSignificantBitsCount(norm) - 1
	if bitCountDiff < 0 {
		bitCountDiff = 0
	}

	return bitCountDiff
}

func getSignificantBitsCount(x *big.Int) int {

	bitCount := x.BitLen()

	if bitCount == 0 {
		return 0
	}

	if bitCount <= 32 {
		return int(math.Round(math.Log2(float64(x.Uint64()))))
	}

	numOne := 0
	for i := 1; i <= 12; i++ {
		if x.Bit(bitCount-1-i) == 1 {
			numOne++
		}
		if numOne < 6 {
			bitCount--
		}
	}

	return bitCount
}
