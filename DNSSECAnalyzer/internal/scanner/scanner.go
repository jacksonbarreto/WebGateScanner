package scanner

import (
	"bytes"
	"fmt"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/config"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/internal/domainextractor"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/pkg/models"
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/pkg/models/dnsrecords"
	"os"
	"os/exec"
)

type Scanner struct {
	parsers     map[string]dnsrecords.DNSRecordParser
	dnsServerIP string
}

func NewScannerDefault() *Scanner {
	parsers := map[string]dnsrecords.DNSRecordParser{
		"DNSKEY":     &dnsrecords.DNSKEYResponse{},
		"DS":         &dnsrecords.DSResponse{},
		"SOA":        &dnsrecords.SOARecord{},
		"AAAA":       &dnsrecords.AAAAResponse{},
		"A":          &dnsrecords.AResponse{},
		"NSEC":       &dnsrecords.NSECRecord{},
		"NSEC3PARAM": &dnsrecords.NSEC3PARAMRecord{},
	}
	dnsServer := config.App().DNSServer
	return NewScanner(dnsServer, parsers)
}

func NewScanner(dnsServerIP string, parsers map[string]dnsrecords.DNSRecordParser) *Scanner {
	return &Scanner{
		parsers:     parsers,
		dnsServerIP: fmt.Sprintf("@%s", dnsServerIP),
	}
}

func (s *Scanner) Scan(url string) (*models.Assessment, error) {
	domain, err := domainextractor.ExtractDomain(url)
	if err != nil {
		return nil, err
	}
	assessment := models.NewAssessment(url, domain)

	assessment.Begin()
	for recordType, parser := range s.parsers {
		cmd := exec.Command("delv", s.dnsServerIP, domain, recordType)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr
		cmdErr := cmd.Run()
		if cmdErr != nil {
			return nil, cmdErr
		}

		result, parseErr := parser.Parse(out.String())
		if parseErr != nil {
			return nil, parseErr
		}

		assessment.Records[recordType] = result
	}
	assessment.Finish()

	return assessment, nil
}
