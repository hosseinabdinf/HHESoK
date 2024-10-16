package pasta

// Parameter for Pasta cipher
// note: Plaintext and Ciphertext size are both equal in PASTA, we merge both as BlockSize
type Parameter struct {
	KeySize   int
	BlockSize int
	Rounds    int
	Modulus   uint64
}

// GetKeySize returns the secret key size in bits
func (params Parameter) GetKeySize() int {
	return params.KeySize
}

// GetBlockSize returns the plaintext size in bits
func (params Parameter) GetBlockSize() int {
	return params.BlockSize
}

// GetModulus returns modulus
func (params Parameter) GetModulus() uint64 {
	return params.Modulus
}

// GetRounds return rounds
func (params Parameter) GetRounds() int {
	return params.Rounds
}
