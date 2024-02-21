package pasta

import (
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
)

var HEIntParamsN12QP109 = heint.ParametersLiteral{
	LogN:             12,
	LogQ:             []int{39, 31},
	LogP:             []int{39},
	PlaintextModulus: 0x10001,
}

type Parameter struct {
	logN      int
	plainMod  uint64
	modDegree uint64
}

func (params Parameter) NewParameters() {

}

func (params Parameter) NewBFVParametersFromLiteral(literal bfv.ParametersLiteral) bfv.Parameters {
	panic("implement me!")
}
