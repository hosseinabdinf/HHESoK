package pasta

import (
	"HHESoK"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"testing"
)

func TestHEPasta(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipped in -short mode!")
	}
	_ = HHESoK.NewLogger(HHESoK.DEBUG)
	// Generate HE parameters
	p, err := heint.NewParametersFromLiteral(HEIntParamsN12QP109)
	if err != nil {
		t.Fatal(err)
	}
	p.RingQ()
	t.Logf("HEPastaParameters: LogN: %d, LogQP: %12.7f, logSlots: %d \n",
		p.LogN(), p.LogQP(), p.LogMaxSlots())

}
