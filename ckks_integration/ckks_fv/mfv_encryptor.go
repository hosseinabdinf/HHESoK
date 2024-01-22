package ckks_fv

import (
	"HHESoK/ckks_integration/ring"
	"HHESoK/ckks_integration/utils"
)

// MFVEncryptor in an interface for encryptors
//
// encrypt with pk : ciphertext = [pk[0]*u + m + e_0, pk[1]*u + e_1]
// encrypt with sk : ciphertext = [-a*sk + m + e, a]
type MFVEncryptor interface {
	// EncryptNew encrypts the input plaintext using the stored key and returns
	// the result on a newly created ciphertext. The encryption is done by first
	// encrypting zero in QP, dividing by P and then adding the plaintext.
	EncryptNew(plaintext *Plaintext) *Ciphertext

	// Encrypt encrypts the input plaintext using the stored key, and returns
	// the result on the receiver ciphertext. The encryption is done by first
	// encrypting zero in QP, dividing by P and then adding the plaintext.
	Encrypt(plaintext *Plaintext, ciphertext *Ciphertext)

	// EncryptFastNew encrypts the input plaintext using the stored key and returns
	// the result on a newly created ciphertext. The encryption is done by first
	// encrypting zero in Q and then adding the plaintext.
	EncryptFastNew(plaintext *Plaintext) *Ciphertext

	// EncryptFast encrypts the input plaintext using the stored-key, and returns
	// the result on the receiver ciphertext. The encryption is done by first
	// encrypting zero in Q and then adding the plaintext.
	EncryptFast(plaintext *Plaintext, ciphertext *Ciphertext)

	// EncryptFromCRPNew encrypts the input plaintext using the stored key and returns
	// the result on a newly created ciphertext. The encryption is done by first encrypting
	// zero in QP, using the provided polynomial as the uniform polynomial, dividing by P and
	// then adding the plaintext.
	EncryptFromCRPNew(plaintext *Plaintext, crp *ring.Poly) *Ciphertext

	// EncryptFromCRP encrypts the input plaintext using the stored key and returns
	// the result tge receiver ciphertext. The encryption is done by first encrypting
	// zero in QP, using the provided polynomial as the uniform polynomial, dividing by P and
	// then adding the plaintext.
	EncryptFromCRP(plaintext *Plaintext, ciphertext *Ciphertext, crp *ring.Poly)

	// EncryptFromCRPNew encrypts the input plaintext using the stored key and returns
	// the result on a newly created ciphertext. The encryption is done by first encrypting
	// zero in Q, using the provided polynomial as the uniform polynomial, and
	// then adding the plaintext.
	EncryptFromCRPFastNew(plaintext *Plaintext, crp *ring.Poly) *Ciphertext

	// EncryptFromCRP encrypts the input plaintext using the stored key and returns
	// the result tge receiver ciphertext. The encryption is done by first encrypting
	// zero in Q, using the provided polynomial as the uniform polynomial, and
	// then adding the plaintext.
	EncryptFromCRPFast(plaintext *Plaintext, ciphertext *Ciphertext, crp *ring.Poly)
}

// encryptor is a structure that holds the parameters needed to encrypt plaintexts.
type encryptor struct {
	params   *Parameters
	ringQ    *ring.Ring
	ringP    *ring.Ring
	ringQPs  []*ring.Ring
	polypool [3]*ring.Poly
	poolQ    [3]*ring.Poly
	poolP    [3]*ring.Poly

	baseconverter              *ring.FastBasisExtender
	gaussianSampler            *ring.GaussianSampler
	uniformSamplerQ            *ring.UniformSampler
	ternarySamplerQ            *ring.TernarySampler
	ternarySamplerMontgomeryQ  *ring.TernarySampler
	ternarySamplerMontgomeryQP *ring.TernarySampler
}

type pkEncryptor struct {
	encryptor
	pk *PublicKey
}

type skEncryptor struct {
	encryptor
	sk *SecretKey
}

// NewMFVEncryptorFromPk creates a new Encryptor with the provided public-key.
// This encryptor can be used to encrypt plaintexts, using the stored key.
func NewMFVEncryptorFromPk(params *Parameters, pk *PublicKey) MFVEncryptor {
	return &pkEncryptor{newMFVEncryptor(params), pk}
}

// NewMFVEncryptorFromSk creates a new Encryptor with the provided secret-key.
// This encryptor can be used to encrypt plaintexts, using the stored key.
func NewMFVEncryptorFromSk(params *Parameters, sk *SecretKey) MFVEncryptor {
	return &skEncryptor{newMFVEncryptor(params), sk}
}

func newMFVEncryptor(params *Parameters) encryptor {

	var ringQ, ringP *ring.Ring
	var ringQPs []*ring.Ring
	var err error

	if ringQ, err = ring.NewRing(params.N(), params.qi); err != nil {
		panic(err)
	}

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	var baseconverter *ring.FastBasisExtender
	var polypool, poolQ, poolP [3]*ring.Poly
	var ternarySamplerMontgomeryQP *ring.TernarySampler

	if len(params.pi) != 0 {
		if ringP, err = ring.NewRing(params.N(), params.pi); err != nil {
			panic(err)
		}
		baseconverter = ring.NewFastBasisExtender(ringQ, ringP)

		modCount := len(params.qi)
		ringQPs = make([]*ring.Ring, modCount)

		for i := 0; i < modCount; i++ {
			moduli := make([]uint64, i+1)
			copy(moduli, params.qi[:i+1])
			if ringQPs[i], err = ring.NewRing(params.N(), append(moduli, params.pi...)); err != nil {
				panic(err)
			}
		}

		ringQPmax := ringQPs[modCount-1]
		ternarySamplerMontgomeryQP = ring.NewTernarySampler(prng, ringQPmax, 0.5, true)
		polypool = [3]*ring.Poly{ringQPmax.NewPoly(), ringQPmax.NewPoly(), ringQPmax.NewPoly()}
		poolQ = [3]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly()}
		poolP = [3]*ring.Poly{ringP.NewPoly(), ringP.NewPoly(), ringP.NewPoly()}
	} else {
		polypool = [3]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly()}
	}

	return encryptor{
		params:                     params.Copy(),
		ringQ:                      ringQ,
		ringP:                      ringP,
		ringQPs:                    ringQPs,
		polypool:                   polypool,
		poolQ:                      poolQ,
		poolP:                      poolP,
		baseconverter:              baseconverter,
		gaussianSampler:            ring.NewGaussianSampler(prng),
		uniformSamplerQ:            ring.NewUniformSampler(prng, ringQ),
		ternarySamplerQ:            ring.NewTernarySampler(prng, ringQ, 0.5, false),
		ternarySamplerMontgomeryQ:  ring.NewTernarySampler(prng, ringQ, 0.5, true),
		ternarySamplerMontgomeryQP: ternarySamplerMontgomeryQP,
	}
}

func (encryptor *pkEncryptor) EncryptNew(plaintext *Plaintext) *Ciphertext {
	ciphertext := NewCiphertextFVLvl(encryptor.params, 1, plaintext.Level())
	encryptor.encrypt(plaintext, ciphertext, false)
	return ciphertext
}

func (encryptor *pkEncryptor) Encrypt(plaintext *Plaintext, ciphertext *Ciphertext) {

	if encryptor.baseconverter == nil {
		panic("Cannot Encrypt : modulus P is empty -> use instead EncryptFast")
	}

	encryptor.encrypt(plaintext, ciphertext, false)
}

func (encryptor *pkEncryptor) EncryptFastNew(plaintext *Plaintext) *Ciphertext {
	ciphertext := NewCiphertextFVLvl(encryptor.params, 1, plaintext.Level())
	encryptor.encrypt(plaintext, ciphertext, true)

	return ciphertext
}

func (encryptor *pkEncryptor) EncryptFast(plaintext *Plaintext, ciphertext *Ciphertext) {
	encryptor.encrypt(plaintext, ciphertext, true)
}

func (encryptor *pkEncryptor) EncryptFromCRP(plaintext *Plaintext, ciphertext *Ciphertext, crp *ring.Poly) {
	panic("Cannot encrypt with CRP using an encryptor created with the public-key")
}

func (encryptor *pkEncryptor) EncryptFromCRPNew(plaintext *Plaintext, crp *ring.Poly) *Ciphertext {
	panic("Cannot encrypt with CRP using an encryptor created with the public-key")
}

func (encryptor *pkEncryptor) EncryptFromCRPFast(plaintext *Plaintext, ciphertext *Ciphertext, crp *ring.Poly) {
	panic("Cannot encrypt with CRP using an encryptor created with the public-key")
}

func (encryptor *pkEncryptor) EncryptFromCRPFastNew(plaintext *Plaintext, crp *ring.Poly) *Ciphertext {
	panic("Cannot encrypt with CRP using an encryptor created with the public-key")
}

func (encryptor *pkEncryptor) encrypt(p *Plaintext, ciphertext *Ciphertext, fast bool) {

	if p.Level() != ciphertext.Level() {
		panic("cannot encrypt: input and output should have the same level")
	}
	levelQ := p.Level()
	ringQ := encryptor.ringQ

	if fast {

		encryptor.ternarySamplerMontgomeryQ.ReadLvl(levelQ, encryptor.polypool[2])
		ringQ.NTTLazyLvl(levelQ, encryptor.polypool[2], encryptor.polypool[2])

		ringQ.MulCoeffsMontgomeryLvl(levelQ, encryptor.polypool[2], encryptor.pk.Value[0], encryptor.polypool[0])
		ringQ.MulCoeffsMontgomeryLvl(levelQ, encryptor.polypool[2], encryptor.pk.Value[1], encryptor.polypool[1])

		ringQ.InvNTTLvl(levelQ, encryptor.polypool[0], ciphertext.value[0])
		ringQ.InvNTTLvl(levelQ, encryptor.polypool[1], ciphertext.value[1])

		// ct[0] = pk[0]*u + e0
		encryptor.gaussianSampler.ReadAndAddLvl(levelQ, ciphertext.value[0], ringQ, encryptor.params.Sigma(), int(6*encryptor.params.Sigma()))

		// ct[1] = pk[1]*u + e1
		encryptor.gaussianSampler.ReadAndAddLvl(levelQ, ciphertext.value[1], ringQ, encryptor.params.Sigma(), int(6*encryptor.params.Sigma()))

	} else {

		ringQP := encryptor.ringQPs[levelQ]

		polypool := [3]*ring.Poly{ringQP.NewPoly(), ringQP.NewPoly(), ringQP.NewPoly()}
		if levelQ == len(encryptor.params.qi)-1 {
			polypool[0] = encryptor.polypool[0]
			polypool[1] = encryptor.polypool[1]
			polypool[2] = encryptor.polypool[2]
		} else {
			levelQP := levelQ + len(encryptor.params.pi)
			polypool[0].Coeffs = polypool[0].Coeffs[:levelQP+1]
			polypool[1].Coeffs = polypool[1].Coeffs[:levelQP+1]
			polypool[2].Coeffs = polypool[2].Coeffs[:levelQP+1]
		}

		if levelQ == len(encryptor.params.qi)-1 {
			// u
			encryptor.ternarySamplerMontgomeryQP.Read(polypool[2])
			ringQP.NTTLazy(polypool[2], polypool[2])

			// ct[0] = pk[0]*u
			// ct[1] = pk[1]*u
			ringQP.MulCoeffsMontgomery(polypool[2], encryptor.pk.Value[0], polypool[0])
			ringQP.MulCoeffsMontgomery(polypool[2], encryptor.pk.Value[1], polypool[1])

			ringQP.InvNTTLazy(polypool[0], polypool[0])
			ringQP.InvNTTLazy(polypool[1], polypool[1])

			// ct[0] = pk[0]*u + e0
			encryptor.gaussianSampler.ReadAndAdd(polypool[0], ringQP, encryptor.params.Sigma(), int(6*encryptor.params.Sigma()))

			// ct[1] = pk[1]*u + e1
			encryptor.gaussianSampler.ReadAndAdd(polypool[1], ringQP, encryptor.params.Sigma(), int(6*encryptor.params.Sigma()))

			// We rescale the encryption of zero by the special prime, dividing the error by this prime
			encryptor.baseconverter.ModDownPQ(levelQ, polypool[0], ciphertext.value[0])
			encryptor.baseconverter.ModDownPQ(levelQ, polypool[1], ciphertext.value[1])

			// ct[0] = pk[0]*u + e0 + m
			// ct[1] = pk[1]*u + e1
			ringQ.AddLvl(levelQ, ciphertext.value[0], p.value, ciphertext.value[0])
		} else {
			ringP := encryptor.ringP

			poolQ0 := encryptor.poolQ[0]
			poolQ1 := encryptor.poolQ[1]
			poolQ2 := encryptor.poolQ[2]
			poolP0 := encryptor.poolP[0]
			poolP1 := encryptor.poolP[1]
			poolP2 := encryptor.poolP[2]

			encryptor.ternarySamplerQ.ReadLvl(levelQ, poolQ2)
			extendBasisSmallNormAndCenter(ringQ, ringP, poolQ2, poolP2)

			// (#Q + #P) NTT
			ringQ.NTTLvl(levelQ, poolQ2, poolQ2)
			ringP.NTT(poolP2, poolP2)

			ringQ.MFormLvl(levelQ, poolQ2, poolQ2)
			ringP.MForm(poolP2, poolP2)

			pk0P := new(ring.Poly)
			pk1P := new(ring.Poly)
			pk0P.Coeffs = encryptor.pk.Value[0].Coeffs[len(ringQ.Modulus):]
			pk1P.Coeffs = encryptor.pk.Value[1].Coeffs[len(ringQ.Modulus):]

			// ct0 = u*pk0
			// ct1 = u*pk1
			ringQ.MulCoeffsMontgomeryLvl(levelQ, poolQ2, encryptor.pk.Value[0], poolQ0)
			ringQ.MulCoeffsMontgomeryLvl(levelQ, poolQ2, encryptor.pk.Value[1], poolQ1)
			ringP.MulCoeffsMontgomery(poolP2, pk0P, poolP0)
			ringP.MulCoeffsMontgomery(poolP2, pk1P, poolP1)

			// 2*(#Q + #P) NTT
			ringQ.InvNTTLvl(levelQ, poolQ0, poolQ0)
			ringQ.InvNTTLvl(levelQ, poolQ1, poolQ1)
			ringP.InvNTT(poolP0, poolP0)
			ringP.InvNTT(poolP1, poolP1)

			// ct0 = u*pk0 + e0
			encryptor.gaussianSampler.ReadLvl(levelQ, poolQ2, ringQ, encryptor.params.sigma, int(6*encryptor.params.sigma))
			extendBasisSmallNormAndCenter(ringQ, ringP, poolQ2, poolP2)
			ringQ.AddLvl(levelQ, poolQ0, poolQ2, poolQ0)
			ringP.Add(poolP0, poolP2, poolP0)

			// ct1 = u*pk1 + e1
			encryptor.gaussianSampler.ReadLvl(levelQ, poolQ2, ringQ, encryptor.params.sigma, int(6*encryptor.params.sigma))
			extendBasisSmallNormAndCenter(ringQ, ringP, poolQ2, poolP2)
			ringQ.AddLvl(levelQ, poolQ1, poolQ2, poolQ1)
			ringP.Add(poolP1, poolP2, poolP1)

			// ct0 = (u*pk0 + e0)/P + m
			encryptor.baseconverter.ModDownSplitPQ(levelQ, poolQ0, poolP0, ciphertext.value[0])
			ringQ.AddLvl(levelQ, ciphertext.value[0], p.value, ciphertext.value[0])

			// ct1 = (u*pk0 + e1)/P
			encryptor.baseconverter.ModDownSplitPQ(levelQ, poolQ1, poolP1, ciphertext.value[1])
		}
	}
}

func (encryptor *skEncryptor) EncryptNew(plaintext *Plaintext) *Ciphertext {
	ciphertext := NewCiphertextFVLvl(encryptor.params, 1, plaintext.Level())
	encryptor.Encrypt(plaintext, ciphertext)
	return ciphertext
}

func (encryptor *skEncryptor) Encrypt(plaintext *Plaintext, ciphertext *Ciphertext) {
	if plaintext.Level() != ciphertext.Level() {
		panic("cannot Encrypt: input and output should have the same level")
	}
	encryptor.encryptSample(plaintext, ciphertext)
}

func (encryptor *skEncryptor) EncryptFastNew(plaintext *Plaintext) *Ciphertext {
	panic("Cannot EncryptFastNew: not supported by sk encryptor -> use EncryptFastNew instead")
}

func (encryptor *skEncryptor) EncryptFast(plaintext *Plaintext, ciphertext *Ciphertext) {
	panic("Cannot EncryptFast: not supported by sk encryptor -> use Encrypt instead")
}

func (encryptor *skEncryptor) EncryptFromCRPNew(plaintext *Plaintext, crp *ring.Poly) *Ciphertext {
	ciphertext := NewCiphertextFV(encryptor.params, 1)
	encryptor.EncryptFromCRP(plaintext, ciphertext, crp)
	return ciphertext
}

func (encryptor *skEncryptor) EncryptFromCRP(plaintext *Plaintext, ciphertext *Ciphertext, crp *ring.Poly) {
	encryptor.encryptFromCRP(plaintext, ciphertext, crp)
}

func (encryptor *skEncryptor) EncryptFromCRPFastNew(plaintext *Plaintext, crp *ring.Poly) *Ciphertext {
	panic("Cannot EncryptFromCRPFastNew: not supported by sk encryptor -> use EncryptFromCRPNew instead")
}

func (encryptor *skEncryptor) EncryptFromCRPFast(plaintext *Plaintext, ciphertext *Ciphertext, crp *ring.Poly) {
	panic("Cannot EncryptFromCRPFast: not supported by sk encryptor -> use EncryptFromCRP instead")
}

func (encryptor *skEncryptor) encryptSample(plaintext *Plaintext, ciphertext *Ciphertext) {
	encryptor.uniformSamplerQ.Read(encryptor.polypool[1])
	encryptor.encrypt(plaintext, ciphertext, encryptor.polypool[1])
}

func (encryptor *skEncryptor) encryptFromCRP(plaintext *Plaintext, ciphertext *Ciphertext, crp *ring.Poly) {
	encryptor.ringQ.Copy(crp, encryptor.polypool[1])
	encryptor.encrypt(plaintext, ciphertext, encryptor.polypool[1])
}

func (encryptor *skEncryptor) encrypt(p *Plaintext, ciphertext *Ciphertext, crp *ring.Poly) {

	if p.Level() != ciphertext.Level() {
		panic("cannot encrypt: input and output should have the same level")
	}
	level := p.Level()

	ringQ := encryptor.ringQ

	ringQ.MulCoeffsMontgomeryLvl(level, crp, encryptor.sk.Value, ciphertext.value[0])
	ringQ.NegLvl(level, ciphertext.value[0], ciphertext.value[0])

	ringQ.InvNTTLvl(level, ciphertext.value[0], ciphertext.value[0])
	ringQ.InvNTTLvl(level, crp, ciphertext.value[1])

	encryptor.gaussianSampler.ReadAndAddLvl(level, ciphertext.value[0], ringQ, encryptor.params.Sigma(), int(6*encryptor.params.Sigma()))

	// ct = [-a*s + m + e , a]
	encryptor.ringQ.AddLvl(level, ciphertext.value[0], p.value, ciphertext.value[0])
}
