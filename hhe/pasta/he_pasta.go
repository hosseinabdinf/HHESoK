package pasta

import (
	"HHESoK"
	"HHESoK/sym/pasta"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type HEPasta struct {
	logger  HHESoK.Logger
	fvPasta MFVPasta

	params    Parameter
	symParams pasta.Parameter
	bfvParams bgv.Parameters
	encoder   *bgv.Encoder
	evaluator *bgv.Evaluator
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor

	keyGenerator *rlwe.KeyGenerator
	sk           *rlwe.SecretKey
	pk           *rlwe.PublicKey
	rlk          *rlwe.RelinearizationKey
	glk          []*rlwe.GaloisKey
	evk          *rlwe.MemEvaluationKeySet

	symKeyCt *rlwe.Ciphertext

	N       int
	outSize int
}

func NewHEPasta() *HEPasta {
	hePasta := &HEPasta{
		logger:       HHESoK.NewLogger(HHESoK.DEBUG),
		params:       Parameter{},
		symParams:    pasta.Parameter{},
		fvPasta:      nil,
		bfvParams:    bgv.Parameters{},
		encoder:      nil,
		evaluator:    nil,
		encryptor:    nil,
		decryptor:    nil,
		keyGenerator: nil,
		sk:           nil,
		pk:           nil,
		glk:          nil,
		rlk:          nil,
		evk:          nil,
		symKeyCt:     nil,
		N:            0,
		outSize:      0,
	}
	return hePasta
}

func (pas *HEPasta) InitParams(params Parameter, symParams pasta.Parameter) {
	pas.params = params
	pas.symParams = symParams
	pas.outSize = symParams.PlainSize
	pas.N = 1 << params.logN
	// create bfvParams from Literal
	fvParams, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             params.logN,
		LogQ:             []int{60, 59, 59, 57, 57, 55, 55, 53, 53, 51, 51, 47, 47},
		LogP:             []int{57, 57, 55, 55, 53, 53, 51, 51, 47, 47},
		PlaintextModulus: params.plainMod,
	})
	pas.logger.HandleError(err)
	pas.bfvParams = fvParams
}

func (pas *HEPasta) HEKeyGen() {
	params := pas.bfvParams

	pas.keyGenerator = rlwe.NewKeyGenerator(params)
	pas.sk, pas.pk = pas.keyGenerator.GenKeyPairNew()

	pas.encoder = bgv.NewEncoder(params)
	pas.decryptor = bgv.NewDecryptor(params, pas.sk)
	pas.encryptor = bgv.NewEncryptor(params, pas.pk)

	fmt.Printf("=== Parameters : N=%d, T=%d, LogQP = %f, sigma = %T %v, logMaxSlot= %d \n", 1<<params.LogN(), params.PlaintextModulus(), params.LogQP(), params.Xe(), params.Xe(), params.LogMaxSlots())
}

func (pas *HEPasta) InitFvPasta() MFVPasta {
	pas.fvPasta = NEWMFVPasta(pas.params, pas.bfvParams, pas.symParams, pas.encoder, pas.encryptor, pas.evaluator)
	return pas.fvPasta
}

func (pas *HEPasta) CreateGaloisKeys(dataSize int) {
	pas.rlk = pas.keyGenerator.GenRelinearizationKeyNew(pas.sk)
	galEls := pas.fvPasta.GetGaloisElements(dataSize)
	pas.glk = pas.keyGenerator.GenGaloisKeysNew(galEls, pas.sk)
	pas.evk = rlwe.NewMemEvaluationKeySet(pas.rlk, pas.glk...)
	pas.evaluator = bgv.NewEvaluator(pas.bfvParams, pas.evk)
	pas.fvPasta.UpdateEvaluator(pas.evaluator)
}

func (pas *HEPasta) EncryptSymKey(key HHESoK.Key) {
	pas.symKeyCt = pas.fvPasta.EncKey(key)
	pas.logger.PrintMessages(">> Symmetric Key #slots: ", pas.symKeyCt.Slots())
}

func (pas *HEPasta) Transcipher(nonce []byte, dCt []uint64) []*rlwe.Ciphertext {
	tranCipData := pas.fvPasta.Crypt(nonce, pas.symKeyCt, dCt)
	return tranCipData
}

// Decrypt homomorphic ciphertext
func (pas *HEPasta) Decrypt(ciphertext *rlwe.Ciphertext) (res []uint64) {
	tmp := make([]uint64, pas.bfvParams.MaxSlots())
	pt := pas.decryptor.DecryptNew(ciphertext)
	err := pas.encoder.Decode(pt, tmp)
	pas.logger.HandleError(err)
	return tmp[:pas.symParams.PlainSize]
}
