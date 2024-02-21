package pasta

import (
	"HHESoK"
	"HHESoK/rtf_ckks_integration/ckks"
	"HHESoK/sym/pasta"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
)

type HEPasta struct {
	logger       HHESoK.Logger
	params       Parameter
	symParams    pasta.Parameter
	fvPasta      MFVPasta
	bfvParams    bfv.Parameters
	encoder      *bfv.Encoder
	evaluator    *bfv.Evaluator
	encryptor    *rlwe.Encryptor
	decryptor    *rlwe.Decryptor
	keyGenerator *rlwe.KeyGenerator
	sk           *rlwe.SecretKey
	pk           *rlwe.PublicKey
	rlk          *rlwe.RelinearizationKey
	evk          *rlwe.MemEvaluationKeySet
}

func NewHEPasta() *HEPasta {
	//TODO implement me
	hePasta := &HEPasta{
		logger:       HHESoK.NewLogger(HHESoK.DEBUG),
		params:       Parameter{},
		symParams:    pasta.Parameter{},
		fvPasta:      nil,
		bfvParams:    bfv.Parameters{},
		encoder:      nil,
		evaluator:    nil,
		encryptor:    nil,
		decryptor:    nil,
		keyGenerator: nil,
		sk:           nil,
		pk:           nil,
		rlk:          nil,
		evk:          nil,
	}
	return hePasta
}

func (pas *HEPasta) InitParams(params Parameter, symParams pasta.Parameter) {
	pas.params = params
	pas.symParams = symParams

	// create bfvParams from Literal
	ckks.PN14QP411pq
	fvParams, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN:             params.logN,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: params.plainMod,
	})
	pas.logger.HandleError(err)
	pas.bfvParams = fvParams
}

func (pas *HEPasta) HEKeyGen() {
	params := pas.bfvParams

	pas.keyGenerator = rlwe.NewKeyGenerator(params)
	pas.sk, pas.pk = pas.keyGenerator.GenKeyPairNew()
	pas.rlk = pas.keyGenerator.GenRelinearizationKeyNew(pas.sk)
	pas.evk = rlwe.NewMemEvaluationKeySet(pas.rlk)

	pas.encoder = bfv.NewEncoder(params)
	pas.decryptor = bfv.NewDecryptor(params, pas.sk)
	pas.encryptor = bfv.NewEncryptor(params, pas.pk)
	pas.evaluator = bfv.NewEvaluator(params, pas.evk)

	pas.logger.PrintMessages("=== Parameters : N=%d, T=%d, LogQP = %f, sigma = %T %v \n",
		1<<params.LogN(), params.PlaintextModulus(), params.LogQP(), params.Xe(), params.Xe())
}
