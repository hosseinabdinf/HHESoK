package pasta

import (
	"HHESoK"
	"HHESoK/sym/pasta"
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

//nonce := uint64(123456789)
