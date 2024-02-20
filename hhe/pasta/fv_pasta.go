package pasta

import (
	"HHESoK"
	"HHESoK/symcips/pasta"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
	"golang.org/x/crypto/sha3"
)

type MFVPasta interface {
	Crypt() (res []*rlwe.Ciphertext)
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

func (pas *mfvPasta) Crypt() (res []*rlwe.Ciphertext) {

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

func (pas *mfvPasta) addRC(state *rlwe.Ciphertext, roundConstants HHESoK.Block) (res *rlwe.Ciphertext) {
	rcs := bfv.NewPlaintext(pas.bfvParams, pas.bfvParams.MaxLevel())
	err := pas.encoder.Encode(roundConstants, rcs)
	pas.logger.HandleError(err)
	res, err = pas.evaluator.AddNew(state, rcs)
	pas.logger.HandleError(err)
	return
}
