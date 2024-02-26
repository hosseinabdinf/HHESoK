package HHESoK

import (
	"HHESoK/rtf_ckks_integration/utils"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
)

type Key []uint64
type Block []uint64
type Vector3D [][][]uint64
type Plaintext []uint64
type Ciphertext []uint64
type Matrix [][]uint64
type SBox []uint64

const DEBUG = false

type logger struct {
	debug bool
}

func NewLogger(debug bool) Logger {
	return &logger{
		debug: debug,
	}
}

type Logger interface {
	PrintMessage(message string)
	PrintMessages(messages ...interface{})
	PrintDataLen(data []uint64)
	PrintMemUsage(name string)
	HandleError(err error)
}

func (l logger) PrintMessage(message string) {
	if l.debug {
		fmt.Printf("\t--- %s\n", message)
	}
}
func (l logger) PrintMessages(messages ...interface{}) {
	if l.debug {
		for _, message := range messages {
			fmt.Print(message)
		}
		fmt.Println()
	}
}
func (l logger) PrintDataLen(data []uint64) {
	if l.debug {
		fmt.Printf("Len: %d, Data: %d \n", len(data), data)
	}
}
func (l logger) HandleError(err error) {
	if err != nil {
		fmt.Printf("=== LOGGER Error: %s\n", err.Error())
		panic("=== LOGGER Panic: \n ")
	}
}

// PrintMemUsage outputs the current, total and OS memory being used. As well as the
// number of garage collection cycles completed. For info on each,
// see: https://golang.org/pkg/runtime/#MemStats
func (l logger) PrintMemUsage(name string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	mb := 1e6
	alloc := float64(m.Alloc) / mb
	tAlloc := float64(m.TotalAlloc) / mb
	mSys := float64(m.Sys) / mb
	//numGC := m.NumGC
	fmt.Printf(">> %s: \t\t\t\t %7.5f MB \t %7.5f MB \t %7.5f MB\n", name, alloc, tAlloc, mSys)
}

// SaveToFile save the given Plaintext as hexadecimal values to a file
func (p Plaintext) SaveToFile(name string) {
	// Open a file for writing
	file, err := os.Create(name + ".txt")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	// Create a new CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write each element of the slice as a separate row in the CSV file
	for _, val := range p {
		err := writer.Write([]string{fmt.Sprintf("0x0%x", val)})
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(name, " saved to file")
}

// SaveToFile save the given Ciphertext as hexadecimal values to a file
func (c Ciphertext) SaveToFile(name string) {
	// Open a file for writing
	file, err := os.Create(name + ".txt")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	// Create a new CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write each element of the slice as a separate row in the CSV file
	for _, val := range c {
		err := writer.Write([]string{fmt.Sprintf("0x0%x", val)})
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(name, " saved to file")
}

// Uint64ToHex converts a vector of uint64 elements to hexadecimal values
// and print them
func Uint64ToHex(data []uint64) {
	hexData := make([]string, len(data))
	for i, v := range data {
		hexData[i] = fmt.Sprintf("%#x", v)
	}
	fmt.Println(hexData)
}

// ScaleUp scale up the f by p
// and return the integer value
func ScaleUp(f float64, scaleFactor float64) uint64 {
	return uint64(math.Round(f * scaleFactor))
}

// ScaleDown scale an integer value x by p
// and return the floating point value
func ScaleDown(x uint64, scaleFactor float64) float64 {
	return float64(x) / scaleFactor
}

// TestVectorGen to generate random values for test vectors
func TestVectorGen(n int, modulus uint64) {
	nonces := make([][]byte, n)
	for i := 0; i < n; i++ {
		nonces[i] = make([]byte, 8)
		_, err := rand.Read(nonces[i])
		if err != nil {
			panic(err)
		}
	}
	fmt.Print("{")
	for i := 0; i < n; i++ {
		result := bytesToHexWithModulus(nonces[i], modulus)
		fmt.Printf("%s, ", result)
		if (i+1)%4 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Print("}\n")
}

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
