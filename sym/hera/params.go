package hera

type Parameter struct {
	BlockSize int
	Modulus   uint64
	Rounds    int
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
