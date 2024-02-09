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
	modulus            uint64
	params             Parameter
	heParams           HEParameter
	bfvParams          bfv.Parameters
	pas                pasta.Pasta
	encoder            bfv.Encoder
	evaluator          bfv.Evaluator
}

func (hepa *hePasta) NewHEPasta() {
	//TODO implement me
	panic("implement me")
}

func (hepa *hePasta) AddRC(state *rlwe.Ciphertext, roundConstants HHESoK.Block) *rlwe.Ciphertext {
	rcs := bfv.NewPlaintext(hepa.bfvParams, hepa.bfvParams.MaxLevel())
	err := hepa.encoder.Encode(roundConstants, rcs)
	if err != nil {
		panic(err)
	}
	res, err := hepa.evaluator.AddNew(state, rcs)
	if err != nil {
		panic(err)
	}
	return res
}
