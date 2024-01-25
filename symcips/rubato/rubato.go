package rubato

import (
	"HHESoK/ckks_integration/ckks_fv"
	"HHESoK/ckks_integration/ring"
	"HHESoK/ckks_integration/utils"
	"HHESoK/symcips"
	"golang.org/x/crypto/sha3"
)

type Rubato interface {
	NewEncryptor() Encryptor
}

type rubato struct {
	params    Parameter
	shake     sha3.ShakeHash
	secretKey symcips.Key
	state     symcips.Block
	rcs       symcips.Matrix
	p         uint64
	sampler   *ring.GaussianSampler
}

// NewRubato return a new instance of Rubato cipher
func NewRubato(secretKey symcips.Key, params Parameter) Rubato {
	if len(secretKey) != params.GetBlockSize() {
		panic("Invalid Key Length!")
	}

	state := make([]uint64, params.GetBlockSize())
	rub := &rubato{
		params:    params,
		shake:     nil,
		secretKey: secretKey,
		state:     state,
		p:         params.GetModulus(),
		rcs:       nil,
		sampler:   nil,
	}
	return rub
}

func (rub *rubato) NewEncryptor() Encryptor {
	return &encryptor{rub: *rub}
}

// keyStream returns a vector of [BlockSize - 4] uint64 elements as key stream
func (rub *rubato) keyStream(nonce []byte, counter []byte) symcips.Block {
	p := rub.params.GetModulus()
	rounds := rub.params.GetRounds()
	blockSize := rub.params.GetBlockSize()

	rub.initShake(nonce, counter)
	rub.initState()
	rub.initGuSampler()
	rub.generateRCs()

	// Initial AddRoundKey
	for i := 0; i < blockSize; i++ {
		rub.state[i] = (rub.state[i] + rub.rcs[0][i]) % p
	}

	// Round Functions
	for r := 1; r < rounds; r++ {
		rub.linearLayer()
		rub.sBoxFeistel()
		for i := 0; i < blockSize; i++ {
			rub.state[i] = (rub.state[i] + rub.rcs[r][i]) % p
		}
	}

	// Finalization
	rub.linearLayer()
	rub.sBoxFeistel()
	rub.linearLayer()
	if rub.params.GetSigma() > 0 {
		rub.addGaussianNoise()
	}
	for i := 0; i < blockSize; i++ {
		rub.state[i] = (rub.state[i] + rub.rcs[rounds][i]) % p
	}
	rub.state = rub.state[0 : blockSize-4]

	return rub.state
}

func (rub *rubato) initState() {
	for i := 0; i < rub.params.GetBlockSize(); i++ {
		rub.state[i] = uint64(i + 1)
	}
}

func (rub *rubato) initShake(nonce []byte, counter []byte) {
	shake := sha3.NewShake256()
	if _, err := shake.Write(nonce); err != nil {
		panic("Failed to init SHAKE128!")
	}
	if _, err := shake.Write(counter); err != nil {
		panic("Failed to init SHAKE128!")
	}
	rub.shake = shake
}

func (rub *rubato) initGuSampler() {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	rub.sampler = ring.NewGaussianSampler(prng)
}

func (rub *rubato) generateRCs() {
	key := rub.secretKey
	blockSize := rub.params.GetBlockSize()
	p := rub.params.GetModulus()
	rounds := rub.params.GetRounds()
	// generate round constant and then calculate rc = rc * k % p for ARK function
	rcs := make(symcips.Matrix, rounds+1)
	for r := 0; r <= rounds; r++ {
		rcs[r] = make([]uint64, blockSize)
		for i := 0; i < blockSize; i++ {
			rcs[r][i] = ckks_fv.SampleZqx(rub.shake, p) * key[i] % p
		}
	}
	rub.rcs = rcs
}

func (rub *rubato) linearLayer() {
	blockSize := len(rub.state)
	p := rub.params.GetModulus()
	buf := make(symcips.Block, blockSize)

	if blockSize == 16 {
		// MixColumns
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				buf[row*4+col] = 2 * rub.state[row*4+col]
				buf[row*4+col] += 3 * rub.state[((row+1)%4)*4+col]
				buf[row*4+col] += rub.state[((row+2)%4)*4+col]
				buf[row*4+col] += rub.state[((row+3)%4)*4+col]
				buf[row*4+col] %= p
			}
		}
		// MixRows
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				rub.state[row*4+col] = 2 * buf[row*4+col]
				rub.state[row*4+col] += 3 * buf[row*4+(col+1)%4]
				rub.state[row*4+col] += buf[row*4+(col+2)%4]
				rub.state[row*4+col] += buf[row*4+(col+3)%4]
				rub.state[row*4+col] %= p
			}
		}
	} else if blockSize == 36 {
		// MixColumns
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				buf[row*6+col] = 4 * rub.state[row*6+col]
				buf[row*6+col] += 2 * rub.state[((row+1)%6)*6+col]
				buf[row*6+col] += 4 * rub.state[((row+2)%6)*6+col]
				buf[row*6+col] += 3 * rub.state[((row+3)%6)*6+col]
				buf[row*6+col] += rub.state[((row+4)%6)*6+col]
				buf[row*6+col] += rub.state[((row+5)%6)*6+col]
				buf[row*6+col] %= p
			}
		}
		// MixRows
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				rub.state[row*6+col] = 4 * buf[row*6+col]
				rub.state[row*6+col] += 2 * buf[row*6+(col+1)%6]
				rub.state[row*6+col] += 4 * buf[row*6+(col+2)%6]
				rub.state[row*6+col] += 3 * buf[row*6+(col+3)%6]
				rub.state[row*6+col] += buf[row*6+(col+4)%6]
				rub.state[row*6+col] += buf[row*6+(col+5)%6]
				rub.state[row*6+col] %= p
			}
		}
	} else if blockSize == 64 {
		// MixColumns
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				buf[row*8+col] = 5 * rub.state[row*8+col]
				buf[row*8+col] += 3 * rub.state[((row+1)%8)*8+col]
				buf[row*8+col] += 4 * rub.state[((row+2)%8)*8+col]
				buf[row*8+col] += 3 * rub.state[((row+3)%8)*8+col]
				buf[row*8+col] += 6 * rub.state[((row+4)%8)*8+col]
				buf[row*8+col] += 2 * rub.state[((row+5)%8)*8+col]
				buf[row*8+col] += rub.state[((row+6)%8)*8+col]
				buf[row*8+col] += rub.state[((row+7)%8)*8+col]
				buf[row*8+col] %= p
			}
		}
		// MixRows
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				rub.state[row*8+col] = 5 * buf[row*8+col]
				rub.state[row*8+col] += 3 * buf[row*8+(col+1)%8]
				rub.state[row*8+col] += 4 * buf[row*8+(col+2)%8]
				rub.state[row*8+col] += 3 * buf[row*8+(col+3)%8]
				rub.state[row*8+col] += 6 * buf[row*8+(col+4)%8]
				rub.state[row*8+col] += 2 * buf[row*8+(col+5)%8]
				rub.state[row*8+col] += buf[row*8+(col+6)%8]
				rub.state[row*8+col] += buf[row*8+(col+7)%8]
				rub.state[row*8+col] %= p
			}
		}
	} else {
		panic("Invalid block size!")
	}
}

func (rub *rubato) sBoxFeistel() {
	p := rub.params.GetModulus()
	blockSize := rub.params.GetBlockSize()
	buf := make(symcips.Block, blockSize)

	for i := 0; i < blockSize; i++ {
		buf[i] = rub.state[i]
	}

	for i := 1; i < blockSize; i++ {
		rub.state[i] = (buf[i] + buf[i-1]*buf[i-1]) % p
	}
}

func (rub *rubato) addGaussianNoise() {
	bound := int(6 * rub.params.GetSigma())
	rub.sampler.AGN(rub.state, rub.p, rub.params.GetSigma(), bound)
}
