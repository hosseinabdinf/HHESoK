package HHESoK

import (
	"fmt"
	"io"
	"log"
	"math"
	"reflect"
	"runtime"
	"strings"
)

// DEBUG for turning debug logs on/off
const DEBUG = true
const MeMStat = true
const PREFIX = "->> "

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
	PrintFormatted(format string, args ...interface{})
	PrintDataLen(data []uint64)
	PrintHeader(header string)
	PrintMemUsage(name string)
	PrintSummarizedVector(name string, vec []uint64, numElements int)
	PrintSummarizedMatrix(name string, mat [][]interface{}, numRows int, numElements int)
}

func (l logger) PrintMessage(message string) {
	if l.debug {
		fmt.Print(PREFIX)
		fmt.Printf("%s", message)
		fmt.Println()
	}
}

func (l logger) PrintMessages(messages ...interface{}) {
	if l.debug {
		fmt.Print(PREFIX)
		for _, message := range messages {
			fmt.Print(message)
		}
		fmt.Println()
	}
}

func (l logger) PrintFormatted(format string, args ...interface{}) {
	if l.debug {
		fmt.Print(PREFIX)
		fmt.Printf(format, args...)
		fmt.Println()
	}
}

func (l logger) PrintDataLen(data []uint64) {
	if l.debug {
		fmt.Print(PREFIX)
		fmt.Printf("Len: %d, Data: %d", len(data), data)
		fmt.Println()
	}
}

func (l logger) PrintHeader(header string) {
	fmt.Println(fmt.Sprintf("=== ----\t\t\t %s \t\t\t---- ===", header))
}

// HandleError checks the error and throws a fatal log if the error isn't nil
func HandleError(err error) {
	if err != nil {
		fmt.Printf("|-> Error: %s\n", err.Error())
		panic("=== Panic\n ")
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
	buf := new(strings.Builder)
	width := 15 + 7
	_, err := fmt.Fprintf(buf, "|-> %-*s", width, name)
	HandleError(err)
	buf.WriteByte('\t')
	prettyPrint(buf, alloc, "MB")
	buf.WriteByte('\t')
	prettyPrint(buf, tAlloc, "MB")
	buf.WriteByte('\t')
	prettyPrint(buf, mSys, "MB")
	if MeMStat {
		fmt.Println(buf)
	}
}

// Helps to print the MemStats
func prettyPrint(w io.Writer, x float64, unit string) {
	// Print all numbers with 10 places before the decimal point
	// and small numbers with four sig figs. Field widths are
	// chosen to fit the whole part in 10 places while aligning
	// the decimal point of all fractional formats.
	var format string
	switch y := math.Abs(x); {
	case y == 0 || y >= 999.95:
		format = "%10.3f %s"
	case y >= 99.995:
		format = "%10.3f %s"
	case y >= 9.9995:
		format = "%10.3f %s"
	case y >= 0.99995:
		format = "%10.3f %s"
	case y >= 0.099995:
		format = "%15.4f %s"
	case y >= 0.0099995:
		format = "%16.5f %s"
	case y >= 0.00099995:
		format = "%17.6f %s"
	default:
		format = "%18.7f %s"
	}
	_, err := fmt.Fprintf(w, format, x, unit)
	HandleError(err)
}

// PrintSummarizedMatrix prints a summarized view of a matrix
func (l logger) PrintSummarizedMatrix(name string, mat [][]interface{}, numRows int, numElements int) {
	const summaryLength = 5
	if len(mat) == 0 || len(mat[0]) == 0 {
		fmt.Print(PREFIX)
		fmt.Println("Matrix is empty!")
		return
	}
	// Get the kind of the first element in the first row
	v := reflect.TypeOf(mat[0][0])
	format := ""
	switch v.Kind() {
	case reflect.Uint64:
		format = "%d "
	case reflect.Float64:
		format = "%.2f "
	default:
		log.Fatal("Unsupported type")
		return
	}

	if l.debug {
		fmt.Printf("%s:\n", name)
		for i := 0; i < numRows; i++ {
			if i > summaryLength {
				break
			}
			fmt.Printf("[%d][]: {", i)
			if numElements > 2*summaryLength {
				for j := 0; j < summaryLength; j++ {
					fmt.Printf(format, mat[i][j])
				}
				fmt.Printf("... ")
				for j := numElements - summaryLength; j < numElements; j++ {
					fmt.Printf(format, mat[i][j])
				}
			} else {
				for j := 0; j < numElements; j++ {
					fmt.Printf(format, mat[i][j])
				}
			}
			fmt.Printf("}\n")
		}
	}
}

// PrintSummarizedVector prints a summarized view of a vector
func (l logger) PrintSummarizedVector(name string, vec []uint64, numElements int) {
	const summaryLength = 4
	if len(vec) == 0 {
		fmt.Print(PREFIX)
		fmt.Println("Vector is empty!")
		return
	}
	// Get the kind of the first element in the first row
	v := reflect.TypeOf(vec[0])
	format := ""
	switch v.Kind() {
	case reflect.Uint64:
		format = "%d "
	case reflect.Float64:
		format = "%.2f "
	default:
		log.Fatal("Unsupported type")
		return
	}

	if l.debug {
		fmt.Printf("[%s]: {", name)
		if numElements > 2*summaryLength {
			for i := 0; i < summaryLength; i++ {
				fmt.Printf(format, vec[i])
			}
			fmt.Printf("... ")
			for i := numElements - summaryLength; i < numElements; i++ {
				fmt.Printf(format, vec[i])
			}
		} else {
			for i := 0; i < numElements; i++ {
				fmt.Printf(format, vec[i])
			}
		}
		fmt.Printf("}\n")
	}
}
