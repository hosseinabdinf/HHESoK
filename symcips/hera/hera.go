package hera

import (
	"HHESoK/ckks_integration/ckks_fv"
	"HHESoK/symcips"
	"golang.org/x/crypto/sha3"
)

type Hera interface {
	NewEncryptor() Encryptor
}

type hera struct {
	params    Parameter
	shake     sha3.ShakeHash
	secretKey symcips.Key
	state     symcips.Block
	rcs       symcips.Matrix
	p         uint64
}

// NewHera return a new instance of Hera cipher
func NewHera(secretKey symcips.Key, params Parameter) Hera {
	if len(secretKey) != params.GetBlockSize() {
		panic("Invalid Key Length!")
	}

	state := make(symcips.Block, params.GetBlockSize())
	her := &hera{
		params:    params,
		shake:     nil,
		secretKey: secretKey,
		state:     state,
		p:         params.GetModulus(),
		rcs:       nil,
	}
	return her
}

func (her *hera) NewEncryptor() Encryptor {
	return &encryptor{her: *her}
}

func (her *hera) keyStream(nonce []byte) (ks symcips.Block) {
	// init Shake256
	her.initShake(nonce)
	// init state with values between 1 and BlockSize
	her.initState()
	her.generateRCs()
	// round = 0
	her.keySchedule(0)
	// 1 < rounds < r
	for r := 1; r < her.params.GetRounds(); r++ {
		her.mixColumns()
		her.mixRows()
		her.sBoxCube()
		her.keySchedule(r)
	}
	// the last round
	her.mixColumns()
	her.mixRows()
	her.sBoxCube()
	her.mixColumns()
	her.mixRows()
	her.keySchedule(her.params.GetRounds())
	ks = her.state
	return
}

func (her *hera) initState() {
	for i := 0; i < her.params.GetBlockSize(); i++ {
		her.state[i] = uint64(i + 1)
	}
}

func (her *hera) initShake(nonce []byte) {
	shake := sha3.NewShake256()
	if _, err := shake.Write(nonce); err != nil {
		panic("Failed to init SHAKE128!")
	}
	her.shake = shake
}

func (her *hera) generateRCs() {
	key := her.secretKey
	p := her.params.GetModulus()
	rounds := her.params.GetRounds()
	blockSize := her.params.GetBlockSize()

	rcs := make([][]uint64, rounds+1)
	// K * rc_r, where r is round index
	for r := 0; r <= rounds; r++ {
		rcs[r] = make([]uint64, blockSize)
		for i := 0; i < blockSize; i++ {
			rcs[r][i] = ckks_fv.SampleZqx(her.shake, p) * key[i] % p
		}
	}
	her.rcs = rcs
}

func (her *hera) keySchedule(r int) {
	for i := 0; i < her.params.GetBlockSize(); i++ {
		her.state[i] = (her.state[i] + her.rcs[r][i]) % her.params.GetModulus()
	}
}

func (her *hera) mixColumns() {
	p := her.params.GetModulus()
	for col := 0; col < 4; col++ {
		y0 := 2*her.state[col] + 3*her.state[col+4] + 1*her.state[col+8] + 1*her.state[col+12]
		y1 := 2*her.state[col+4] + 3*her.state[col+8] + 1*her.state[col+12] + 1*her.state[col]
		y2 := 2*her.state[col+8] + 3*her.state[col+12] + 1*her.state[col] + 1*her.state[col+4]
		y3 := 2*her.state[col+12] + 3*her.state[col] + 1*her.state[col+4] + 1*her.state[col+8]

		her.state[col] = y0 % p
		her.state[col+4] = y1 % p
		her.state[col+8] = y2 % p
		her.state[col+12] = y3 % p
	}
}

func (her *hera) mixRows() {
	p := her.params.GetModulus()
	for row := 0; row < 4; row++ {
		y0 := 2*her.state[4*row] + 3*her.state[4*row+1] + 1*her.state[4*row+2] + 1*her.state[4*row+3]
		y1 := 2*her.state[4*row+1] + 3*her.state[4*row+2] + 1*her.state[4*row+3] + 1*her.state[4*row]
		y2 := 2*her.state[4*row+2] + 3*her.state[4*row+3] + 1*her.state[4*row] + 1*her.state[4*row+1]
		y3 := 2*her.state[4*row+3] + 3*her.state[4*row] + 1*her.state[4*row+1] + 1*her.state[4*row+2]

		her.state[4*row] = y0 % p
		her.state[4*row+1] = y1 % p
		her.state[4*row+2] = y2 % p
		her.state[4*row+3] = y3 % p
	}
}

func (her *hera) sBoxCube() {
	p := her.params.GetModulus()
	for i := 0; i < her.params.GetBlockSize(); i++ {
		her.state[i] = (her.state[i] * her.state[i] % p) * her.state[i] % p
	}
}
