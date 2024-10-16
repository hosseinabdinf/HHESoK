package HHESoK

import (
	"HHESoK/rtf_ckks_integration/utils"
	"fmt"
	"strings"
)

func bytesToHexWithModulus(data []byte, modulus uint64) string {
	// Convert bytes to uint64 and take modulus
	result := make([]uint64, len(data)/8)
	for i := 0; i < len(data)/8; i++ {
		result[i] = uint64(data[i*8]) |
			uint64(data[i*8+1])<<8 |
			uint64(data[i*8+2])<<16 |
			uint64(data[i*8+3])<<24 |
			uint64(data[i*8+4])<<32 |
			uint64(data[i*8+5])<<40 |
			uint64(data[i*8+6])<<48 |
			uint64(data[i*8+7])<<56

		result[i] %= modulus
	}

	// Convert uint64 to hexadecimal string
	hexValues := make([]string, len(result))
	for i, v := range result {
		hexValues[i] = fmt.Sprintf("%#x", v)
	}

	// Join hexadecimal values into a string
	return strings.Join(hexValues, ", ")
}

// RandomFloatDataGen to generate a matrix of floating point numbers between 0 and 1
func RandomFloatDataGen(col int, row int) (data [][]float64) {
	data = make([][]float64, row)
	for s := 0; s < row; s++ {
		data[s] = make([]float64, col)
		for i := 0; i < col; i++ {
			data[s][i] = utils.RandFloat64(0, 1)
		}
	}
	return
}

// Scale data to save as []uint64
//delta := float64(tc.params.GetModulus()) / float64(N)
//for s := 0; s < optSize; s++ {
//	plaintext := func() []uint64 {
//		result := make([]uint64, len(data[s]))
//		for i, v := range data[s] {
//			result[i] = sym.ScaleUp(v, delta)
//		}
//		return result
//	}()
//	fmt.Println("Len: ", len(plaintext), " - OG: ", data[0])
//	sym.Uint64ToHex(plaintext)
//fmt.Println(">  Encrypt() the data[", s, "]")

// RotateSlice to rotate a slice by a given offset
func RotateSlice(slice Block, offset uint64) {
	l := len(slice)
	if l == 0 {
		return
	}

	// Normalize offset to be within the slice's length
	offset %= uint64(l)
	// Rotate the slice elements
	Reverse(slice[:offset])
	Reverse(slice[offset:])
	Reverse(slice)
}

// Reverse to reverse a slice
func Reverse(slice Block) {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// ResizeSlice resize the old slice
func ResizeSlice(oldSlice Block, newLen uint64) (newSlice Block) {
	l := uint64(len(oldSlice))
	if newLen == l {
		newSlice = oldSlice
	} else if newLen > l {
		newSlice = append(oldSlice, make(Block, newLen-l)...)
	} else {
		newSlice = oldSlice[:newLen]
	}
	return
}
