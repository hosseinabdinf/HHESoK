package pasta

import (
	"HHESoK"
	"HHESoK/sym/pasta"
	"encoding/binary"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
	"golang.org/x/crypto/sha3"
	"math"
	"math/big"
)

type MFVPasta interface {
	Crypt() (nonce uint64, kCt *rlwe.Ciphertext, dCt HHESoK.Ciphertext)
	EncKey(key []uint64) (res *rlwe.Ciphertext)
}

type mfvPasta struct {
	logger   HHESoK.Logger
	numRound int

	plainSize    uint64
	slots        uint64
	halfSlots    uint64
	plainMod     uint64
	modDegree    uint64
	modulus      uint64
	maxPrimeSize uint64

	shake sha3.ShakeHash
	mat1  HHESoK.Matrix
	mat2  HHESoK.Matrix

	state *rlwe.Ciphertext

	N        int
	useBatch bool
	useBsGs  bool
	bsGsN1   uint64
	bsGsN2   uint64

	pas       pasta.Pasta
	bfvParams bfv.Parameters
	encryptor rlwe.Encryptor
	decryptor rlwe.Decryptor
	encoder   bfv.Encoder
	evaluator bfv.Evaluator

	rcPt *rlwe.Plaintext
	rc   HHESoK.Block
}

func NEWMFVPasta(modDegree uint64, params pasta.Parameter, encoder bfv.Encoder, encryptor rlwe.Encryptor, evaluator bfv.Evaluator) MFVPasta {
	fvPasta := new(mfvPasta)
	fvPasta.logger = HHESoK.NewLogger(HHESoK.DEBUG)

	fvPasta.N = 0
	fvPasta.useBatch = true
	fvPasta.useBsGs = false
	fvPasta.bsGsN1 = 0
	fvPasta.bsGsN2 = 0
	fvPasta.modDegree = modDegree

	fvPasta.encoder = encoder
	fvPasta.encryptor = encryptor
	fvPasta.evaluator = evaluator

	mps := uint64(0) // max prime size
	prime := modDegree

	// count the number of valid bits of prime number, using shift to right operation
	for prime > 0 {
		mps++
		prime >>= 1
	}

	// set mps to the maximum value that can be represented with mps bits
	mps = (1 << mps) - 1

	// init empty states
	//fvPasta.state = make(*rlwe.Ciphertext, params.GetPlainSize())

	return fvPasta
}

func (pas *mfvPasta) Crypt(nonce uint64, kCt *rlwe.Ciphertext, dCt HHESoK.Ciphertext) (res []*rlwe.Ciphertext) {
	size := len(dCt)
	numBlock := uint64(math.Ceil(float64(size / int(pas.plainSize))))

	res = make([]*rlwe.Ciphertext, numBlock)

	for b := uint64(0); b < numBlock; b++ {
		pas.initShake(nonce, b)
		state := kCt.CopyNew()
		R := pas.numRound
		for r := 1; r <= R; r++ {
			pas.logger.PrintMessages(">>> Round: ", r, " <<<")
			// initialize random matrices and random constant
			pas.mat1 = pas.genRandomMatrix()
			pas.mat2 = pas.genRandomMatrix()
			pas.rc = pas.genRcVector(pas.halfSlots)

			// PASTA key stream generation circuit
			pas.matMul()
			pas.addRC()
			pas.mix()

			if r == R {
				pas.sBoxCube()
			} else {
				pas.sBoxFeistel()
			}
			//	print noise for state in each round
		}
		//	final addition
		pas.mat1 = pas.genRandomMatrix()
		pas.mat2 = pas.genRandomMatrix()
		pas.rc = pas.genRcVector(pas.halfSlots)

		pas.matMul()
		pas.addRC()
		pas.mix()

		var sIndex = b * pas.plainSize
		var eIndex = int(math.Min(float64((b+1)*pas.plainSize), float64(size)))
		tempCipher := dCt[sIndex:eIndex]
		plaintext := bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
		_ = pas.encoder.Encode(tempCipher, plaintext)
		// negate state
		state, _ = pas.evaluator.MulNew(state, -1)
		res[b], _ = pas.evaluator.AddNew(state, plaintext)
	}
	return
}

func (pas *mfvPasta) EncKey(key []uint64) (res *rlwe.Ciphertext) {
	tmpKey := make([]uint64, pas.halfSlots+pas.plainSize)
	for i := uint64(0); i < pas.plainSize; i++ {
		tmpKey[i] = key[i]
		tmpKey[i+pas.halfSlots] = key[i+pas.plainSize]
	}

	pKey := bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
	err := pas.encoder.Encode(tmpKey, pKey)
	pas.logger.HandleError(err)

	err = pas.encryptor.Encrypt(pKey, res)
	pas.logger.HandleError(err)

	return
}

// ///////////////////////		PASTA's homomorphic functions		///////////////////////

func (pas *mfvPasta) addRC() {
	pas.rcPt = bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
	err := pas.encoder.Encode(pas.rc, pas.rcPt)
	pas.logger.HandleError(err)
	err = pas.evaluator.Add(pas.state, pas.rcPt, pas.state)
	pas.logger.HandleError(err)
	return
}

func (pas *mfvPasta) sBoxCube() {
	tmp := pas.state.CopyNew()
	err := pas.evaluator.MulRelin(pas.state, pas.state, pas.state)
	pas.logger.HandleError(err)
	err = pas.evaluator.MulRelin(pas.state, tmp, pas.state)
	pas.logger.HandleError(err)
}

func (pas *mfvPasta) sBoxFeistel() {
	// rotate -1 to the left
	stateRotate, err := pas.evaluator.RotateColumnsNew(pas.state, -1)
	pas.logger.HandleError(err)

	// generate masks
	masks := make(HHESoK.Block, pas.plainMod+pas.halfSlots)
	for i := range masks {
		masks[i] = 1
	}
	masks[0] = 0
	masks[pas.halfSlots] = 0
	for i := pas.plainMod; i < pas.halfSlots; i++ {
		masks[i] = 0
	}
	maskPlaintext := bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
	err = pas.encoder.Encode(masks, maskPlaintext)
	pas.logger.HandleError(err)
	// stateRot = stateRot * mask
	err = pas.evaluator.Mul(stateRotate, maskPlaintext, stateRotate)
	pas.logger.HandleError(err)
	// stateRot = stateRot ^ 2
	err = pas.evaluator.MulRelin(stateRotate, stateRotate, stateRotate)
	pas.logger.HandleError(err)
	// state = state + stateRot^2
	err = pas.evaluator.Add(pas.state, stateRotate, pas.state)
	pas.logger.HandleError(err)
}

func (pas *mfvPasta) matMul() {
	if pas.useBsGs {
		pas.babyStepGiantStep()
	} else {
		pas.diagonal()
	}
	return
}

func (pas *mfvPasta) babyStepGiantStep() {
	var err error
	matrixDim := pas.plainMod
	slots := pas.slots

	if (matrixDim*2 != slots) && (matrixDim*4 > slots) {
		panic("Slots are too short for matmul implementation!")
	}

	if pas.bsGsN1*pas.bsGsN2 != matrixDim {
		println("WARNING: the baby-step giant-step parameters are wrong!")
	}

	// Prepare diagonal
	matrix := make([]*rlwe.Plaintext, matrixDim)
	for i := uint64(0); i < matrixDim; i++ {
		diag := make(HHESoK.Block, matrixDim+pas.halfSlots)
		tmp := make(HHESoK.Block, matrixDim)

		k := i / pas.bsGsN1
		for j := uint64(0); j < matrixDim; j++ {
			diag[j] = pas.mat1[j][(j+matrixDim-i)%matrixDim]
			tmp[j] = pas.mat2[j][(j+matrixDim-i)%matrixDim]
		}

		//	rotate
		if k > 0 {
			HHESoK.RotateSlice(diag, k*pas.bsGsN1)
			HHESoK.RotateSlice(tmp, k*pas.bsGsN1)
		}

		//	non-full pack rotation
		if pas.halfSlots != pas.plainMod {
			diag = diag[:pas.halfSlots]
			tmp = tmp[:pas.halfSlots]

			// Perform the element swapping loop
			for m := uint64(0); m < k*pas.bsGsN1; m++ {
				indexSrc := pas.plainMod - 1 - m
				indexDest := pas.halfSlots - 1 - m
				diag[indexDest] = diag[indexSrc]
				diag[indexSrc] = 0
				tmp[indexDest] = tmp[indexSrc]
				tmp[indexSrc] = 0
			}
		}

		// Combine both diags
		diag = append(diag, make([]uint64, pas.halfSlots)...)
		for j := pas.halfSlots; j < slots; j++ {
			diag[j] = tmp[j-pas.halfSlots]
		}

		row := bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
		err = pas.encoder.Encode(diag, row)
		pas.logger.HandleError(err)
		matrix[i] = row
	}

	//	non-full-packed rotation
	if pas.halfSlots != pas.plainMod {
		stateRotate := pas.state.CopyNew()
		err = pas.evaluator.RotateColumns(pas.state, int(pas.plainMod), stateRotate)
		pas.logger.HandleError(err)
		err = pas.evaluator.Add(pas.state, stateRotate, pas.state)
		pas.logger.HandleError(err)
	}

	rotates := make([]*rlwe.Ciphertext, pas.bsGsN1)
	rotates[0] = pas.state

	var outerSum *rlwe.Ciphertext
	for j := uint64(1); j < pas.bsGsN1; j++ {
		err = pas.evaluator.RotateColumns(rotates[j-1], -1, rotates[j])
		pas.logger.HandleError(err)
	}

	for k := uint64(0); k < pas.bsGsN2; k++ {
		innerSum, _ := pas.evaluator.MulNew(rotates[0], matrix[k*pas.bsGsN1])
		for j := uint64(1); j < pas.bsGsN1; j++ {
			temp, _ := pas.evaluator.MulNew(rotates[0], matrix[k*pas.bsGsN1+j])
			_ = pas.evaluator.Add(innerSum, temp, innerSum)
		}
		if k == 0 {
			outerSum = innerSum
		} else {
			innerSum, _ = pas.evaluator.RotateColumnsNew(innerSum, -int(k*pas.bsGsN1))
			_ = pas.evaluator.Add(outerSum, innerSum, outerSum)
		}
	}
	pas.state = outerSum
}

func (pas *mfvPasta) diagonal() {
	var err error
	matrixDim := pas.plainMod
	slots := pas.slots

	if (matrixDim*2 != slots) && (matrixDim*4 > slots) {
		panic("Slots are too short for matmul implementation!")
	}

	if pas.halfSlots != matrixDim {
		stateRotate, _ := pas.evaluator.RotateColumnsNew(pas.state, int(matrixDim))
		err = pas.evaluator.Add(pas.state, stateRotate, pas.state)
		pas.logger.HandleError(err)
	}

	//	prepare diagonal method
	matrix := make([]*rlwe.Plaintext, matrixDim)
	for i := uint64(0); i < matrixDim; i++ {
		diag := make(HHESoK.Block, matrixDim+pas.halfSlots)
		for j := range diag {
			diag[j] = 0
		}

		for j := uint64(0); j < matrixDim; j++ {
			diag[j] = pas.mat1[j][(j+matrixDim-i)%matrixDim]
			diag[j+pas.halfSlots] = pas.mat2[j][(j+matrixDim-i)%matrixDim]
		}

		row := bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
		err = pas.encoder.Encode(diag, row)
		pas.logger.HandleError(err)
		matrix[i] = row
	}

	sum := pas.state.CopyNew()
	err = pas.evaluator.Mul(sum, matrix[0], sum)
	pas.logger.HandleError(err)
	for i := uint64(1); i < matrixDim; i++ {
		pas.state, _ = pas.evaluator.RotateColumnsNew(pas.state, -1)
		tmp, _ := pas.evaluator.MulNew(pas.state, matrix[i])
		_ = pas.evaluator.Add(sum, tmp, sum)
	}
	pas.state = sum
}

func (pas *mfvPasta) mix() {
	originalState := pas.state.CopyNew()
	tmp, err := pas.evaluator.RotateRowsNew(pas.state)
	pas.logger.HandleError(err)
	err = pas.evaluator.Add(tmp, originalState, tmp)
	pas.logger.HandleError(err)
	err = pas.evaluator.Add(originalState, tmp, pas.state)
	pas.logger.HandleError(err)
}

// ///////////////////////		PASTA's non-homomorphic functions	///////////////////////
func (pas *mfvPasta) initShake(nonce uint64, counter uint64) {
	seed := make([]byte, 16)

	binary.BigEndian.PutUint64(seed[:8], nonce)
	binary.BigEndian.PutUint64(seed[8:], counter)

	shake := sha3.NewShake128()
	if _, err := shake.Write(seed); err != nil {
		panic("Failed to init SHAKE128!")
	}

	pas.shake = shake
}

func (pas *mfvPasta) genRandomMatrix() HHESoK.Matrix {
	ps := pas.plainSize
	mat := make(HHESoK.Matrix, ps) // mat[ps][ps]
	for i := range mat {
		mat[i] = make(HHESoK.Block, ps) // mat[i] = [ps]
	}
	mat[0] = pas.genRandomVector(false)
	for j := uint64(1); j < ps; j++ {
		mat[j] = pas.calculateRow(mat[j-1], mat[0])
	}
	return mat
}

func (pas *mfvPasta) genRcVector(size uint64) HHESoK.Block {
	ps := pas.plainSize
	rc := make(HHESoK.Block, size+ps)
	for i := uint64(0); i < ps; i++ {
		rc[i] = pas.generateRandomFieldElement(false)
	}
	for i := size; i < (size + ps); i++ {
		rc[i] = pas.generateRandomFieldElement(false)
	}
	return rc
}

func (pas *mfvPasta) genRandomVector(allowZero bool) HHESoK.Block {
	ps := pas.plainSize
	rc := make(HHESoK.Block, ps)
	for i := uint64(0); i < ps; i++ {
		rc[i] = pas.generateRandomFieldElement(allowZero)
	}
	return rc
}

func (pas *mfvPasta) generateRandomFieldElement(allowZero bool) uint64 {
	var randomByte [8]byte
	for {
		if _, err := pas.shake.Read(randomByte[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}

		fieldElement := binary.BigEndian.Uint64(randomByte[:]) & pas.maxPrimeSize

		if !allowZero && fieldElement == 0 {
			continue
		}

		if fieldElement < pas.plainMod {
			return fieldElement
		}
	}
}

func (pas *mfvPasta) calculateRow(previousRow, firstRow HHESoK.Block) HHESoK.Block {
	ps := pas.plainSize
	modulus := new(big.Int).SetUint64(pas.plainMod)
	output := make(HHESoK.Block, ps)
	// =======================================
	pRow := new(big.Int).SetUint64(previousRow[ps-1])

	for j := uint64(0); j < ps; j++ {
		fRow := new(big.Int).SetUint64(firstRow[j])
		temp := new(big.Int).Mul(fRow, pRow)
		temp.Mod(temp, modulus)
		// update the index row and add the value to the temp
		if j > 0 {
			indexRow := new(big.Int).SetUint64(previousRow[j-1])
			temp.Add(temp, indexRow)
			temp.Mod(temp, modulus)
		}

		output[j] = temp.Uint64()
	}
	return output
}
