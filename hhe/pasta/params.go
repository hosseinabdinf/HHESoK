package pasta

import (
	"HHESoK"
	"HHESoK/symcips/pasta"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
)

type Parameter struct {
	KeySize    int
	PlainSize  int
	CipherSize int
}

var HEIntParamsN12QP109 = heint.ParametersLiteral{
	LogN:             12,
	LogQ:             []int{39, 31},
	LogP:             []int{39},
	PlaintextModulus: 0x10001,
}

type HEParameter struct {
	secretKey          HHESoK.Key
	params             pasta.Parameter
	plainMod           uint64
	modDegree          uint64
	secretKeyEncrypted *rlwe.Ciphertext
	heSK               rlwe.SecretKey
	hePK               rlwe.PublicKey
	heRK               rlwe.RelinearizationKey
	heEVK              rlwe.EvaluationKey

	//heGK               GaloisKey
}

func (params Parameter) getKeySize() int {
	return params.KeySize
}

func (params Parameter) getPlainSize() int {
	return params.PlainSize
}

func (params Parameter) getCipherSize() int {
	return params.CipherSize
}

func (params Parameter) NewParameters() {

}

func (params Parameter) NewBFVParametersFromLiteral(literal bfv.ParametersLiteral) bfv.Parameters {
	panic("implement me!")
}
