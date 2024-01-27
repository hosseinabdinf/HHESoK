package symcips

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
)

type Key []uint64
type Block []uint64
type Vector3D [][][]uint64
type Plaintext []uint64
type Ciphertext []uint64
type Matrix [][]uint64
type SBox []uint64

func PrintLog(msg string) {
	fmt.Printf("\t--- %s\n", msg)
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
