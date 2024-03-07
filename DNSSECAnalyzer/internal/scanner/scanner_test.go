package scanner

import (
	"fmt"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/config"
	"testing"
)

func TestScan(t *testing.T) {
	config.InitConfig("../../")
	scan := NewScannerDefault()

	result, err := scan.Scan("www.ipb.pt")
	if err != nil {
		t.Errorf("Scan failed")
	}
	fmt.Print(result)
}
