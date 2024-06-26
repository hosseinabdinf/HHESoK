package pasta

// Parameter for Pasta cipher
type Parameter struct {
	KeySize    int
	PlainSize  int
	CipherSize int
	Rounds     int
	Modulus    uint64
}

// GetKeySize returns the secret key size in bits
func (params Parameter) GetKeySize() int {
	return params.KeySize
}

// GetPlainSize returns the plaintext size in bits
func (params Parameter) GetPlainSize() int {
	return params.PlainSize
}

// GetCipherSize returns the ciphertext size in bits
func (params Parameter) GetCipherSize() int {
	return params.CipherSize
}

// GetModulus returns modulus
func (params Parameter) GetModulus() uint64 {
	return params.Modulus
}

// GetRounds return rounds
func (params Parameter) GetRounds() int {
	return params.Rounds
}
