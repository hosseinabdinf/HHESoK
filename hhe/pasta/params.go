package pasta

import (
	"HHESoK/symcips"
	"HHESoK/symcips/pasta"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type FvPastaParameter struct {
	KeySize    int
	PlainSize  int
	CipherSize int
}

type FvParameter struct {
	secretKey          symcips.Key
	params             pasta.Parameter
	plainMod           uint64
	modDegree          uint64
	secretKeyEncrypted *rlwe.Ciphertext
	heSK               rlwe.SecretKey
	hePK               rlwe.PublicKey
	heRK               rlwe.RelinearizationKey
	//heGK               GaloisKey
}

func (params FvPastaParameter) getKeySize() int {
	return params.KeySize
}

func (params FvPastaParameter) getPlainSize() int {
	return params.PlainSize
}

func (params FvPastaParameter) getCipherSize() int {
	return params.CipherSize
}

func (params FvPastaParameter) NewParameters() {

}
