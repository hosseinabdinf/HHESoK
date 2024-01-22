package symcips

import (
	"encoding/csv"
	"fmt"
	"os"
)

type Key []uint64
type Block []uint64
type Vector3D [][][]uint64
type Plaintext []uint64
type Ciphertext []uint64
type Matrix [][]uint64
type SBox []uint64

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
