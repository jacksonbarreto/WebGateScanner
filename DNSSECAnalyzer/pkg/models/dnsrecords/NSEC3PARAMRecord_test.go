package dnsrecords

import (
	"strings"
	"testing"
)

func TestNewNSEC3ParamRecordGoodResponse(t *testing.T) {
	response := goodNsec3ParamResponse
	expected := &NSEC3PARAMRecord{
		TTL:           0,
		HashAlgorithm: 1,
		Flags:         0,
		Iterations:    0,
		SaltLength:    0,
		Validated:     true,
		RRSIG: &RRSIGRecord{
			TypeCovered: "NSEC3PARAM",
			Algorithm:   13,
			Labels:      1,
			OriginalTTL: 0,
			Expiration:  1704505090,
			Inception:   1703254046,
			KeyTag:      52707,
			SignerName:  "nl",
			Signature:   "+mydY1Cl3PzERN0rA54wl7JnUdxyVio9ygJVkZWgqtsSNHzUGQpywBtPdwmRNIHInyBoeDlXrw/lRjrD9aCTmA==",
		},
		RawResponse: response,
	}
	r := &NSEC3PARAMRecord{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3Param record: %v", err)
	}

	nsecRecord, ok := result.(*NSEC3PARAMRecord)
	if !ok {
		t.Fatalf("Result is not a *NSEC3PARAMRecord")
	}

	if !nsecRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", nsecRecord, expected)
	}
}

func TestNewNSEC3ParamRecordBadResponse(t *testing.T) {
	response := badNsec3ParamResponse
	r := &NSEC3PARAMRecord{}
	result, err := r.Parse(response)
	if err == nil {
		t.Fatalf("Expected resolution failed error, got nil")
	}
	nsecRecord, ok := result.(*NSEC3PARAMRecord)
	if ok {
		t.Fatalf("Expected nil NSEC3Param response, got %+v", nsecRecord)
	}
	if nsecRecord != nil {
		t.Fatalf("Expected nil NSEC3Param response, got %+v", nsecRecord)
	}

	if !strings.Contains(err.Error(), "resolution failed") {
		t.Errorf("Expected error to contain 'resolution failed', got: %v", err)
	}
}

const goodNsec3ParamResponse = `; fully validated
nl.                     0       IN      NSEC3PARAM 1 0 0 -
nl.                     0       IN      RRSIG   NSEC3PARAM 13 1 0 20240106013810 20231222140726 52707 nl. +mydY1Cl3PzERN0rA54wl7JnUdxyVio9ygJVkZWgqtsSNHzUGQpywBtP dwmRNIHInyBoeDlXrw/lRjrD9aCTmA==`

const badNsec3ParamResponse = `;; resolution failed: ncache nxrrset
; negative response, fully validated
; uminho.pt.            300     IN      \-NSEC3PARAM ;-$NXRRSET
; uminho.pt. SOA dns.uminho.pt. servicos.scom.uminho.pt. 2023121501 14400 7200 1209600 300
; uminho.pt. RRSIG SOA ...
; uminho.pt. RRSIG NSEC ...
; uminho.pt. NSEC 2c2t.uminho.pt. NS SOA MX TXT RRSIG NSEC DNSKEY`
