package pasta

import (
	"HHESoK/symcips"
	"HHESoK/symcips/pasta"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type FvPasta interface {
	NewFvPasta()
}

type fv_pasta struct {
	symmetricSecretKey symcips.Key
	modulus            uint64
	fvPasParams        FvPastaParameter
	pas                pasta.Pasta
	// BFV stuff
	params    bfv.Parameters
	keygen    rlwe.KeyGenerator
	secretKey rlwe.SecretKey
	encryptor rlwe.Encryptor
	decryptor rlwe.Decryptor
	encoder   bfv.Encoder
	evaluator bfv.Evaluator
}

func (fvp *fv_pasta) NewFvPasta() {
	//TODO implement me
	panic("implement me")
}

//func NewFvPasta(sySecKey symcips.Key, fvPasParams FvPastaParameter, r int) FvPasta {
//
//	fvPasta := &fv_pasta{
//		symmetricSecretKey: nil,
//		modulus:            0,
//		fvPasParams:        FvPastaParameter{},
//		params:             bfv.Parameters{},
//		keygen:             nil,
//		secretKey:          rlwe.SecretKey{},
//		encryptor:          nil,
//		decryptor:          nil,
//		encoder:            nil,
//		evaluator:          nil,
//	}
//
//	return fvPasta
//}
