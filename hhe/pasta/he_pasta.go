package pasta

import (
	"HHESoK"
	"HHESoK/symcips/pasta"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
)

type HEPasta interface {
	NewHEPasta()
}

type hePasta struct {
	symmetricSecretKey HHESoK.Key
	bSgS               bool
	bsgsN1             uint64
	bsgsN2             uint64
	modulus            uint64
	halfSlots          uint64
	params             Parameter
	bfvParams          bfv.Parameters
	pas                pasta.Pasta
	encryptor          rlwe.Encryptor
	decryptor          rlwe.Decryptor
	encoder            bfv.Encoder
	evaluator          bfv.Evaluator
}

func (hepa *hePasta) NewHEPasta() {
	//TODO implement me
	panic("implement me")
}

func (hepa *hePasta) addRC(state *rlwe.Ciphertext, roundConstants HHESoK.Block) (res *rlwe.Ciphertext) {
	rcs := bfv.NewPlaintext(hepa.bfvParams, hepa.bfvParams.MaxLevel())
	err := hepa.encoder.Encode(roundConstants, rcs)
	if err != nil {
		panic(err)
	}
	res, err = hepa.evaluator.AddNew(state, rcs)
	if err != nil {
		panic(err)
	}
	return res
}

func (hepa *hePasta) sBoxCube(state *rlwe.Ciphertext) (res *rlwe.Ciphertext) {
	res = state.CopyNew()
	res, err := hepa.evaluator.MulRelinNew(state, state)
	if err != nil {
		panic(err)
	}
	res, err = hepa.evaluator.MulRelinNew(state, res)
	if err != nil {
		panic(err)
	}
	return res
}

func (hepa *hePasta) sBoxFeistel(state *rlwe.Ciphertext) (res *rlwe.Ciphertext) {
	res = state.CopyNew()
	iState := state.CopyNew()
	// rotate -1 to the left
	stateRotate, err := hepa.evaluator.RotateColumnsNew(state, -1)
	if err != nil {
		panic(err)
	}
	// generate masks
	masks := make(HHESoK.Block, hepa.params.plainMod+hepa.halfSlots)
	for i := range masks {
		masks[i] = 1
	}
	masks[0] = 0
	masks[hepa.halfSlots] = 0
	for i := hepa.params.plainMod; i < hepa.halfSlots; i++ {
		masks[i] = 0
	}
	maskPlaintext := bfv.NewPlaintext(hepa.bfvParams, hepa.bfvParams.MaxLevel())
	err = hepa.encoder.Encode(masks, maskPlaintext)
	if err != nil {
		panic(err)
	}
	res, err = hepa.evaluator.MulNew(stateRotate, maskPlaintext)
	if err != nil {
		panic(err)
	}
	res, err = hepa.evaluator.MulRelinNew(res, res)
	if err != nil {
		panic(err)
	}
	res, err = hepa.evaluator.AddNew(iState, res)
	if err != nil {
		panic(err)
	}
	return res
}

func (hepa *hePasta) matMul(state *rlwe.Ciphertext, mat1, mat2 HHESoK.Matrix) (res *rlwe.Ciphertext) {
	if hepa.bSgS {
		res = hepa.babyStepGiantStep(state, mat1, mat2)
	} else {
		res = hepa.diagonal(state, mat1, mat2)
	}
	return
}

func (hepa *hePasta) babyStepGiantStep(state *rlwe.Ciphertext, mat1, mat2 HHESoK.Matrix) *rlwe.Ciphertext {
	matrixDim := hepa.params.plainMod
	slots := 2 * hepa.halfSlots

	if (matrixDim*2 != slots) && (matrixDim*4 > slots) {
		panic("Slots are too short for matmul implementation!")
	}

	if hepa.bsgsN1*hepa.bsgsN2 != matrixDim {
		println("WARNING: the baby step giant step parameters are wrong!")
	}

	// Prepare diagonal
	matrix := make([]*rlwe.Plaintext, matrixDim)
	for i := uint64(0); i < matrixDim; i++ {
		diag := make(HHESoK.Block, matrixDim+hepa.halfSlots)
		tmp := make(HHESoK.Block, matrixDim)

		k := i / hepa.bsgsN1
		for j := uint64(0); j < matrixDim; j++ {
			diag[j] = mat1[j][(j+matrixDim-i)%matrixDim]
			tmp[j] = mat2[j][(j+matrixDim-i)%matrixDim]
		}

		//	rotate
		if k > 0 {
			HHESoK.RotateSlice(diag, k*hepa.bsgsN1)
			HHESoK.RotateSlice(tmp, k*hepa.bsgsN1)
		}

		//	non-full pack rotation
		if hepa.halfSlots != hepa.params.plainMod {
			diag = diag[:hepa.halfSlots]
			tmp = tmp[:hepa.halfSlots]

			// Perform the element swapping loop
			for m := uint64(0); m < k*hepa.bsgsN1; m++ {
				indexSrc := hepa.params.plainMod - 1 - m
				indexDest := hepa.halfSlots - 1 - m
				diag[indexDest] = diag[indexSrc]
				diag[indexSrc] = 0
				tmp[indexDest] = tmp[indexSrc]
				tmp[indexSrc] = 0
			}
		}

		// Combine both diags
		diag = append(diag, make([]uint64, slots-hepa.halfSlots)...)
		for j := hepa.halfSlots; j < slots; j++ {
			diag[j] = tmp[j-hepa.halfSlots]
		}

		row := bfv.NewPlaintext(hepa.bfvParams, hepa.bfvParams.MaxLevel())
		err := hepa.encoder.Encode(diag, row)
		if err != nil {
			panic(err)
		}
		matrix[i] = row
	}

	//	non-full-packed rotation
	if hepa.halfSlots != hepa.params.plainMod {
		stateRotate, _ := hepa.evaluator.RotateColumnsNew(state, int(hepa.params.plainMod))
		state, _ = hepa.evaluator.AddNew(state, stateRotate)
	}

	rotates := make([]*rlwe.Ciphertext, hepa.bsgsN1)
	rotates[0] = state

	var outerSum *rlwe.Ciphertext
	for j := uint64(1); j < hepa.bsgsN1; j++ {
		rotates[j], _ = hepa.evaluator.RotateColumnsNew(rotates[j-1], -1)
	}

	for k := uint64(0); k < hepa.bsgsN2; k++ {
		innerSum, _ := hepa.evaluator.MulNew(rotates[0], matrix[k*hepa.bsgsN1])
		for j := uint64(1); j < hepa.bsgsN1; j++ {
			temp, _ := hepa.evaluator.MulNew(rotates[0], matrix[k*hepa.bsgsN1+j])
			innerSum, _ = hepa.evaluator.AddNew(innerSum, temp)
		}
		if k == 0 {
			outerSum = innerSum
		} else {
			innerSum, _ = hepa.evaluator.RotateColumnsNew(innerSum, int(-1*(k*hepa.bsgsN1)))
			outerSum, _ = hepa.evaluator.AddNew(outerSum, innerSum)
		}
	}
	// todo: make sure about outerSum
	return outerSum
}

func (hepa *hePasta) diagonal(state *rlwe.Ciphertext, mat1, mat2 HHESoK.Matrix) *rlwe.Ciphertext {
	matrixDim := hepa.params.plainMod
	slots := 2 * hepa.halfSlots

	if (matrixDim*2 != slots) && (matrixDim*4 > slots) {
		panic("Slots are too short for matmul implementation!")
	}

	if hepa.halfSlots != matrixDim {
		stateRotate, _ := hepa.evaluator.RotateColumnsNew(state, int(matrixDim))
		state, _ = hepa.evaluator.AddNew(state, stateRotate)
	}

	//	prepare diagonal method
	matrix := make([]*rlwe.Plaintext, matrixDim)
	for i := uint64(0); i < matrixDim; i++ {
		diag := make(HHESoK.Block, matrixDim+hepa.halfSlots)
		for j := range diag {
			diag[j] = 0
		}

		for j := uint64(0); j < matrixDim; j++ {
			diag[j] = mat1[j][(j+matrixDim-i)%matrixDim]
			diag[j+hepa.halfSlots] = mat2[j][(j+matrixDim-i)%matrixDim]
		}

		row := bfv.NewPlaintext(hepa.bfvParams, hepa.bfvParams.MaxLevel())
		err := hepa.encoder.Encode(diag, row)
		if err != nil {
			panic(err)
		}
		matrix[i] = row
	}

	sum := state.CopyNew()
	sum, _ = hepa.evaluator.MulNew(sum, matrix[0])
	for i := uint64(1); i < matrixDim; i++ {
		state, _ = hepa.evaluator.RotateColumnsNew(state, -1)
		tmp, _ := hepa.evaluator.MulNew(state, matrix[i])
		sum, _ = hepa.evaluator.AddNew(sum, tmp)
	}
	return sum
}

func (hepa *hePasta) mix(state *rlwe.Ciphertext) *rlwe.Ciphertext {
	iState := state.CopyNew()
	tmp, _ := hepa.evaluator.RotateRowsNew(state)
	tmp, _ = hepa.evaluator.AddNew(tmp, iState)
	res, _ := hepa.evaluator.AddNew(iState, tmp)
	return res
}
