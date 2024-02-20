package ckks_fv

import (
	"HHESoK/rtf_ckks_integration/ring"
	"fmt"
	"golang.org/x/crypto/sha3"
)

type MFVHera interface {
	Crypt(nonce [][]byte, kCt []*Ciphertext, heraModDown []int) []*Ciphertext
	CryptNoModSwitch(nonce [][]byte, kCt []*Ciphertext) []*Ciphertext
	CryptAutoModSwitch(nonce [][]byte, kCt []*Ciphertext, noiseEstimator MFVNoiseEstimator) (res []*Ciphertext, heraModDown []int)
	Reset(nbInitModDown int)
	EncKey(key []uint64) (res []*Ciphertext)
}

type mfvHera struct {
	numRound      int
	slots         int
	nbInitModDown int

	params    *Parameters
	encoder   MFVEncoder
	encryptor MFVEncryptor
	evaluator MFVEvaluator

	stCt []*Ciphertext
	mkCt []*Ciphertext
	rkCt []*Ciphertext   // Buffer for round key
	rc   [][][]uint64    // RoundConstants[round][state][slot]
	rcPt []*PlaintextMul // Buffer for round constants
	xof  []sha3.ShakeHash
}

func NewMFVHera(numRound int, params *Parameters, encoder MFVEncoder, encryptor MFVEncryptor, evaluator MFVEvaluator, nbInitModDown int) MFVHera {
	hera := new(mfvHera)

	hera.numRound = numRound
	hera.slots = params.FVSlots()
	hera.nbInitModDown = nbInitModDown

	hera.params = params
	hera.encoder = encoder
	hera.encryptor = encryptor
	hera.evaluator = evaluator

	hera.stCt = make([]*Ciphertext, 16)
	hera.mkCt = make([]*Ciphertext, 16)
	hera.rkCt = make([]*Ciphertext, 16)
	hera.rcPt = make([]*PlaintextMul, 16)
	hera.xof = make([]sha3.ShakeHash, hera.slots)

	hera.rc = make([][][]uint64, hera.numRound+1)
	for r := 0; r <= hera.numRound; r++ {
		hera.rc[r] = make([][]uint64, 16)
		for st := 0; st < 16; st++ {
			hera.rc[r][st] = make([]uint64, hera.slots)
		}
	}

	// Precompute Initial States
	state := make([]uint64, hera.slots)

	for i := 0; i < 16; i++ {
		for j := 0; j < hera.slots; j++ {
			state[j] = uint64(i + 1) // ic = 1, ..., 16
		}
		icPT := NewPlaintextFV(params)
		encoder.EncodeUintSmall(state, icPT)
		encryptor.EncryptNew(icPT)
		hera.stCt[i] = encryptor.EncryptNew(icPT)
		if nbInitModDown > 0 {
			evaluator.ModSwitchMany(hera.stCt[i], hera.stCt[i], nbInitModDown)
		}
	}
	return hera
}

func (hera *mfvHera) Reset(nbInitModDown int) {
	// Precompute Initial States
	hera.nbInitModDown = nbInitModDown
	state := make([]uint64, hera.slots)

	for i := 0; i < 16; i++ {
		for j := 0; j < hera.slots; j++ {
			state[j] = uint64(i + 1) // ic = 1, ..., 16
		}
		icPT := NewPlaintextFV(hera.params)
		hera.encoder.EncodeUintSmall(state, icPT)
		hera.encryptor.EncryptNew(icPT)
		hera.stCt[i] = hera.encryptor.EncryptNew(icPT)
		if nbInitModDown > 0 {
			hera.evaluator.ModSwitchMany(hera.stCt[i], hera.stCt[i], nbInitModDown)
		}
	}
}

// Compute Round Constants
func (hera *mfvHera) init(nonce [][]byte) {
	slots := hera.slots
	for i := 0; i < slots; i++ {
		hera.xof[i] = sha3.NewShake256()
		hera.xof[i].Write(nonce[i])
	}

	for r := 0; r <= hera.numRound; r++ {
		for st := 0; st < 16; st++ {
			for slot := 0; slot < slots; slot++ {
				hera.rc[r][st][slot] = SampleZqx(hera.xof[slot], hera.params.PlainModulus())
			}
		}
	}

	for st := 0; st < 16; st++ {
		nbSwitch := hera.mkCt[st].Level() - hera.stCt[st].Level()
		if nbSwitch > 0 {
			hera.evaluator.ModSwitchMany(hera.mkCt[st], hera.mkCt[st], nbSwitch)
		}
	}
}

func (hera *mfvHera) findBudgetInfo(noiseEstimator MFVNoiseEstimator) (maxInvBudget, minErrorBits int) {
	plainModulus := ring.NewUint(hera.params.PlainModulus())
	maxInvBudget = 0
	minErrorBits = 0
	for i := 0; i < 16; i++ {
		invBudget := noiseEstimator.InvariantNoiseBudget(hera.stCt[i])
		errorBits := hera.params.LogQLvl(hera.stCt[i].Level()) - plainModulus.BitLen() - invBudget

		if invBudget > maxInvBudget {
			maxInvBudget = invBudget
			minErrorBits = errorBits
		}
	}
	return
}

func (hera *mfvHera) modSwitchAuto(round int, noiseEstimator MFVNoiseEstimator, heraModDown []int) {
	lvl := hera.stCt[0].Level()

	QiLvl := hera.params.Qi()[:lvl+1]
	LogQiLvl := make([]int, lvl+1)
	for i := 0; i < lvl+1; i++ {
		tmp := ring.NewUint(QiLvl[i])
		LogQiLvl[i] = tmp.BitLen()
	}

	invBudgetOld, errorBitsOld := hera.findBudgetInfo(noiseEstimator)
	nbModSwitch, targetErrorBits := 0, errorBitsOld
	for {
		targetErrorBits -= LogQiLvl[lvl-nbModSwitch]
		if targetErrorBits > 0 {
			nbModSwitch++
		} else {
			break
		}
	}
	if nbModSwitch != 0 {
		tmp := hera.stCt[0].CopyNew().Ciphertext()
		hera.evaluator.ModSwitchMany(hera.stCt[0], hera.stCt[0], nbModSwitch)
		invBudgetNew, _ := hera.findBudgetInfo(noiseEstimator)

		if invBudgetOld-invBudgetNew > 3 {
			nbModSwitch--
		}
		hera.stCt[0] = tmp
	}

	if nbModSwitch > 0 {
		heraModDown[round] = nbModSwitch
		for i := 0; i < 16; i++ {
			hera.evaluator.ModSwitchMany(hera.stCt[i], hera.stCt[i], nbModSwitch)
			hera.evaluator.ModSwitchMany(hera.mkCt[i], hera.mkCt[i], nbModSwitch)
		}

		invBudgetNew, errorBitsNew := hera.findBudgetInfo(noiseEstimator)
		fmt.Printf("Hera Round %d [Budget | Error] : [%v | %v] -> [%v | %v]\n", round, invBudgetOld, errorBitsOld, invBudgetNew, errorBitsNew)
		fmt.Printf("Hera modDown : %v\n\n", heraModDown)
	}
}

func (hera *mfvHera) modSwitch(nbSwitch int) {
	if nbSwitch <= 0 {
		return
	}
	for i := 0; i < 16; i++ {
		hera.evaluator.ModSwitchMany(hera.stCt[i], hera.stCt[i], nbSwitch)
		hera.evaluator.ModSwitchMany(hera.mkCt[i], hera.mkCt[i], nbSwitch)
	}
}

// CryptNoModSwitch Compute ciphertexts without modulus switching
func (hera *mfvHera) CryptNoModSwitch(nonce [][]byte, kCt []*Ciphertext) []*Ciphertext {
	for st := 0; st < 16; st++ {
		hera.mkCt[st] = kCt[st].CopyNew().Ciphertext()
	}
	hera.init(nonce)

	hera.addRoundKey(0, false)
	for r := 1; r < hera.numRound; r++ {
		hera.linLayer()
		hera.cube()
		hera.addRoundKey(r, false)
	}
	hera.linLayer()
	hera.cube()
	hera.linLayer()
	hera.addRoundKey(hera.numRound, true)
	return hera.stCt
}

// CryptAutoModSwitch Compute ciphertexts with automatic modulus switching
func (hera *mfvHera) CryptAutoModSwitch(nonce [][]byte, kCt []*Ciphertext, noiseEstimator MFVNoiseEstimator) ([]*Ciphertext, []int) {
	heraModDown := make([]int, hera.numRound+1)
	heraModDown[0] = hera.nbInitModDown
	for st := 0; st < 16; st++ {
		hera.mkCt[st] = kCt[st].CopyNew().Ciphertext()
	}
	hera.init(nonce)

	hera.addRoundKey(0, false)
	for r := 1; r < hera.numRound; r++ {
		hera.linLayer()
		hera.cube()
		hera.modSwitchAuto(r, noiseEstimator, heraModDown)
		hera.addRoundKey(r, false)
	}
	hera.linLayer()
	hera.cube()
	hera.modSwitchAuto(hera.numRound, noiseEstimator, heraModDown)
	hera.linLayer()
	hera.addRoundKey(hera.numRound, true)
	return hera.stCt, heraModDown
}

// Crypt Compute ciphertexts with modulus switching as given in heraModDown
func (hera *mfvHera) Crypt(nonce [][]byte, kCt []*Ciphertext, heraModDown []int) []*Ciphertext {
	if heraModDown[0] != hera.nbInitModDown {
		errorString := fmt.Sprintf("nbInitModDown expected %d but %d given", hera.nbInitModDown, heraModDown[0])
		panic(errorString)
	}

	for st := 0; st < 16; st++ {
		hera.mkCt[st] = kCt[st].CopyNew().Ciphertext()
	}
	hera.init(nonce)

	hera.addRoundKey(0, false)
	for r := 1; r < hera.numRound; r++ {
		hera.linLayer()
		hera.cube()
		hera.modSwitch(heraModDown[r])
		hera.addRoundKey(r, false)
	}
	hera.linLayer()
	hera.cube()
	hera.modSwitch(heraModDown[hera.numRound])
	hera.linLayer()
	hera.addRoundKey(hera.numRound, true)
	return hera.stCt
}

func (hera *mfvHera) addRoundKey(round int, reduce bool) {
	ev := hera.evaluator

	for st := 0; st < 16; st++ {
		hera.rcPt[st] = NewPlaintextMulLvl(hera.params, hera.stCt[st].Level())
		hera.encoder.EncodeUintMulSmall(hera.rc[round][st], hera.rcPt[st])
	}

	for st := 0; st < 16; st++ {
		hera.rkCt[st] = hera.evaluator.MulNew(hera.mkCt[st], hera.rcPt[st])
	}

	for st := 0; st < 16; st++ {
		if reduce {
			ev.Add(hera.stCt[st], hera.rkCt[st], hera.stCt[st])
		} else {
			ev.AddNoMod(hera.stCt[st], hera.rkCt[st], hera.stCt[st])
		}
	}
}

func (hera *mfvHera) linLayer() {
	ev := hera.evaluator

	for col := 0; col < 4; col++ {
		sum := ev.AddNoModNew(hera.stCt[col], hera.stCt[col+4])
		ev.AddNoMod(sum, hera.stCt[col+8], sum)
		ev.AddNoMod(sum, hera.stCt[col+12], sum)

		y0 := ev.AddNoModNew(sum, hera.stCt[col])
		ev.AddNoMod(y0, hera.stCt[col+4], y0)
		ev.AddNoMod(y0, hera.stCt[col+4], y0)

		y1 := ev.AddNoModNew(sum, hera.stCt[col+4])
		ev.AddNoMod(y1, hera.stCt[col+8], y1)
		ev.AddNoMod(y1, hera.stCt[col+8], y1)

		y2 := ev.AddNoModNew(sum, hera.stCt[col+8])
		ev.AddNoMod(y2, hera.stCt[col+12], y2)
		ev.AddNoMod(y2, hera.stCt[col+12], y2)

		y3 := ev.AddNoModNew(sum, hera.stCt[col+12])
		ev.AddNoMod(y3, hera.stCt[col], y3)
		ev.AddNoMod(y3, hera.stCt[col], y3)

		ev.Reduce(y0, hera.stCt[col])
		ev.Reduce(y1, hera.stCt[col+4])
		ev.Reduce(y2, hera.stCt[col+8])
		ev.Reduce(y3, hera.stCt[col+12])
	}

	for row := 0; row < 4; row++ {
		sum := ev.AddNoModNew(hera.stCt[4*row], hera.stCt[4*row+1])
		ev.AddNoMod(sum, hera.stCt[4*row+2], sum)
		ev.AddNoMod(sum, hera.stCt[4*row+3], sum)

		y0 := ev.AddNoModNew(sum, hera.stCt[4*row])
		ev.AddNoMod(y0, hera.stCt[4*row+1], y0)
		ev.AddNoMod(y0, hera.stCt[4*row+1], y0)

		y1 := ev.AddNoModNew(sum, hera.stCt[4*row+1])
		ev.AddNoMod(y1, hera.stCt[4*row+2], y1)
		ev.AddNoMod(y1, hera.stCt[4*row+2], y1)

		y2 := ev.AddNoModNew(sum, hera.stCt[4*row+2])
		ev.AddNoMod(y2, hera.stCt[4*row+3], y2)
		ev.AddNoMod(y2, hera.stCt[4*row+3], y2)

		y3 := ev.AddNoModNew(sum, hera.stCt[4*row+3])
		ev.AddNoMod(y3, hera.stCt[4*row], y3)
		ev.AddNoMod(y3, hera.stCt[4*row], y3)

		ev.Reduce(y0, hera.stCt[4*row])
		ev.Reduce(y1, hera.stCt[4*row+1])
		ev.Reduce(y2, hera.stCt[4*row+2])
		ev.Reduce(y3, hera.stCt[4*row+3])
	}
}

func (hera *mfvHera) cube() {
	ev := hera.evaluator
	for st := 0; st < 16; st++ {
		x2 := ev.MulNew(hera.stCt[st], hera.stCt[st])
		y2 := ev.RelinearizeNew(x2)
		x3 := ev.MulNew(y2, hera.stCt[st])
		hera.stCt[st] = ev.RelinearizeNew(x3)
	}
}

func (hera *mfvHera) EncKey(key []uint64) (res []*Ciphertext) {
	slots := hera.slots
	res = make([]*Ciphertext, 16)

	for i := 0; i < 16; i++ {
		dupKey := make([]uint64, slots)
		for j := 0; j < slots; j++ {
			dupKey[j] = key[i]
		}

		keyPt := NewPlaintextFV(hera.params)
		hera.encoder.EncodeUintSmall(dupKey, keyPt)
		res[i] = hera.encryptor.EncryptNew(keyPt)
		if hera.nbInitModDown > 0 {
			hera.evaluator.ModSwitchMany(res[i], res[i], hera.nbInitModDown)
		}
	}
	return
}
