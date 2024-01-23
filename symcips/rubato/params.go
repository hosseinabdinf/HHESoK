package rubato

type Parameter struct {
	BlockSize int
	Modulus   uint64
	Rounds    int
	Sigma     float64
}

func (params Parameter) GetBlockSize() int {
	return params.BlockSize
}
func (params Parameter) GetModulus() uint64 {
	return params.Modulus
}
func (params Parameter) GetRounds() int {
	return params.Rounds
}
func (params Parameter) GetSigma() float64 {
	return params.Sigma
}
