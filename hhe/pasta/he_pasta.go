package pasta

import (
	"HHESoK"
	"HHESoK/rtf_ckks_integration/utils"
	"HHESoK/sym/pasta"
	"fmt"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
)

type HEPasta struct {
	logger  HHESoK.Logger
	fvPasta MFVPasta

	params    Parameter
	symParams pasta.Parameter
	bfvParams bfv.Parameters
	encoder   *bfv.Encoder
	evaluator *bfv.Evaluator
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor

	keyGenerator *rlwe.KeyGenerator
	sk           *rlwe.SecretKey
	pk           *rlwe.PublicKey
	rlk          *rlwe.RelinearizationKey
	glk          []*rlwe.GaloisKey
	evk          *rlwe.MemEvaluationKeySet

	symKeyCts      []*rlwe.Ciphertext
	symKeyCt       *rlwe.Ciphertext
	plainBFVRingTs []*rlwe.Plaintext
	plaintexts     []*rlwe.Plaintext

	N            int
	outSize      int
	coefficients [][]uint64
}

func NewHEPasta() *HEPasta {
	hePasta := &HEPasta{
		logger:         HHESoK.NewLogger(HHESoK.DEBUG),
		params:         Parameter{},
		symParams:      pasta.Parameter{},
		fvPasta:        nil,
		bfvParams:      bfv.Parameters{},
		encoder:        nil,
		evaluator:      nil,
		encryptor:      nil,
		decryptor:      nil,
		keyGenerator:   nil,
		sk:             nil,
		pk:             nil,
		glk:            nil,
		rlk:            nil,
		evk:            nil,
		symKeyCts:      nil,
		symKeyCt:       nil,
		plainBFVRingTs: nil,
		plaintexts:     nil,
		coefficients:   nil,
		N:              0,
		outSize:        0,
	}
	return hePasta
}

func (pas *HEPasta) InitParams(params Parameter, symParams pasta.Parameter) {
	pas.params = params
	pas.symParams = symParams
	pas.outSize = symParams.PlainSize
	pas.N = 1 << params.logN
	// create bfvParams from Literal
	fvParams, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
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

	pas.encoder = bfv.NewEncoder(params)
	pas.decryptor = bfv.NewDecryptor(params, pas.sk)
	pas.encryptor = bfv.NewEncryptor(params, pas.pk)

	fmt.Printf("=== Parameters : N=%d, T=%d, LogQP = %f, sigma = %T %v, logMaxSlot= %d \n",
		1<<params.LogN(), params.PlaintextModulus(), params.LogQP(), params.Xe(), params.Xe(), params.LogMaxSlots())
}

func (pas *HEPasta) InitFvPasta() MFVPasta {
	pas.fvPasta = NEWMFVPasta(
		pas.params,
		pas.bfvParams,
		pas.symParams,
		pas.encoder,
		pas.encryptor,
		pas.evaluator)
	return pas.fvPasta
}

func (pas *HEPasta) InitEvaluator(dCt HHESoK.Ciphertext) {
	dataSize := len(dCt)
	pas.rlk = pas.keyGenerator.GenRelinearizationKeyNew(pas.sk)
	galEls := pas.fvPasta.GetGaloisElements(dataSize)
	pas.glk = pas.keyGenerator.GenGaloisKeysNew(galEls, pas.sk)
	pas.evk = rlwe.NewMemEvaluationKeySet(pas.rlk, pas.glk...)
	pas.evaluator = bfv.NewEvaluator(pas.bfvParams, pas.evk)
	pas.fvPasta.UpdateEvaluator(pas.evaluator)
}

// InitCoefficients initialize the coefficient matrix
// coefficients = [out size * number of block]
func (pas *HEPasta) InitCoefficients() {
	pas.coefficients = make([][]uint64, pas.outSize)
	for s := 0; s < pas.outSize; s++ {
		pas.coefficients[s] = make([]uint64, pas.N)
	}
}

// RandomDataGen generates the matrix of random data
// = [output size * number of block]
func (pas *HEPasta) RandomDataGen() (data [][]uint64) {
	data = make([][]uint64, pas.outSize)
	for i := 0; i < pas.outSize; i++ {
		data[i] = make([]uint64, pas.N)
		for j := 0; j < pas.N; j++ {
			data[i][j] = utils.RandUint64()
		}
	}
	return
}

func (pas *HEPasta) DataToCoefficients(data [][]uint64) {
	for s := 0; s < pas.outSize; s++ {
		for i := 0; i < pas.N/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(pas.bfvParams.LogN()-1))
			pas.coefficients[s][j] = data[s][i]
			pas.coefficients[s][j+uint64(pas.N/2)] = data[s][i+pas.bfvParams.N()/2]
		}
	}
}

// EncodeEncrypt Encode plaintext and Encrypt with key stream
func (pas *HEPasta) EncodeEncrypt(keystream [][]uint64) {
	pas.plainBFVRingTs = make([]*rlwe.Plaintext, pas.outSize)
	for s := 0; s < pas.outSize; s++ {
		tmpPt := bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
		err := pas.encoder.Encode(pas.coefficients[s], tmpPt)
		pas.logger.HandleError(err)
		pas.plainBFVRingTs[s] = tmpPt
		poly := pas.plainBFVRingTs[s].Value
		for i := 0; i < pas.N; i++ {
			j := utils.BitReverse64(uint64(i), uint64(pas.bfvParams.LogN()))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % pas.bfvParams.PlaintextModulus()
		}
	}
}

func (pas *HEPasta) EncryptSymKey(key HHESoK.Key) {
	pas.symKeyCts = pas.fvPasta.EncKey(key)
	pas.logger.PrintMessages(">> Symmetric Key Length: ", len(pas.symKeyCts))
}

func (pas *HEPasta) EncryptSymKeyPack(key HHESoK.Key) {
	pas.symKeyCt = pas.fvPasta.EncKeyPack(key)
	pas.logger.PrintMessages(">> Symmetric Key #slots: ", pas.symKeyCt.Slots())
}

func (pas *HEPasta) Trancipher(nonce uint64, dCt HHESoK.Ciphertext) []*rlwe.Ciphertext {
	tranCipData := pas.fvPasta.Crypt(nonce, pas.symKeyCts, dCt)
	return tranCipData
}

func (pas *HEPasta) TrancipherPack(nonce uint64, dCt []uint64) []*rlwe.Ciphertext {
	tranCipData := pas.fvPasta.CryptPack(nonce, pas.symKeyCt, dCt)
	return tranCipData
}

// Decrypt homomorphic ciphertext
func (pas *HEPasta) Decrypt(ciphertexts *rlwe.Ciphertext) (res HHESoK.Plaintext) {
	//params := enc.hepa.params
	//dec := enc.hepa.decryptor
	//en := enc.hepa.encoder
	//
	//res = make(HHESoK.Plaintext, params.GetPlainSize())
	//plaintext := dec.DecryptNew(ciphertexts)
	//err := en.Decode(plaintext, res)
	//if err != nil {
	//	panic(err)
	//}
	//
	return
}
