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
	shake256  sha3.ShakeHash
	secretKey symcips.Key
	state     symcips.Block
	rcs       symcips.Matrix
	p         uint64
	rounds    int
}

// NewHera return a new instance of hera cipher
func NewHera(secretKey symcips.Key, params Parameter, r int) Hera {
	if len(secretKey) != params.GetKeySize() {
		panic("Invalid Key Length!")
	}

	//state = make([]uint64, 16)
	state := make(symcips.Block, params.GetPlainSize())
	her := &hera{
		params:    params,
		shake256:  nil,
		secretKey: secretKey,
		state:     state,
		rounds:    r,
		p:         params.GetModulus(),
		rcs:       nil,
	}
	return her
}

func (her *hera) NewEncryptor() Encryptor {
	return &encryptor{her: *her}
}

func (her *hera) keyStream(nonce []byte) symcips.Block {
	// init Shake256
	her.initShake(nonce)

	// init state with values between 1 and 16
	her.initState()

	her.generateRCs()

	// round = 0
	her.keySchedule(0)

	// 1 < rounds < r
	for r := 1; r < her.rounds; r++ {
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
	her.keySchedule(her.rounds)

	return her.state
}

func (her *hera) initState() {
	for i := 0; i < 16; i++ {
		her.state[i] = uint64(i + 1)
	}
}

func (her *hera) initShake(nonce []byte) {
	shake := sha3.NewShake256()
	if _, err := shake.Write(nonce); err != nil {
		panic("Failed to init SHAKE128!")
	}
	her.shake256 = shake
}

func (her *hera) generateRCs() {
	key := her.secretKey
	p := her.params.GetModulus()
	r := her.rounds

	rcs := make([][]uint64, r+1)
	// K * rc_i, where i is round index
	for r := 0; r <= r; r++ {
		rcs[r] = make([]uint64, 16)
		for st := 0; st < 16; st++ {
			rcs[r][st] = ckks_fv.SampleZqx(her.shake256, p) * key[st] % p
		}
	}
	her.rcs = rcs
}

func (her *hera) keySchedule(r int) {
	for st := 0; st < 16; st++ {
		her.state[st] = (her.state[st] + her.rcs[r][st]) % her.params.GetModulus()
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
	for st := 0; st < 16; st++ {
		her.state[st] = (her.state[st] * her.state[st] % p) * her.state[st] % p
	}
}
