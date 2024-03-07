package dnsrecords

import (
	"strings"
	"testing"
)

func TestNewAAAARecordOK(t *testing.T) {
	response := goodAAAAResponse
	expected := &AAAAResponse{
		Records: []AAAARecord{
			{
				IPv6:        "2001:690:22c0:201::4",
				OriginalTTL: 3600,
			},
		},
		Validated: true,
		RRSIG: &RRSIGRecord{
			TypeCovered: "AAAA",
			Algorithm:   7,
			Labels:      2,
			OriginalTTL: 3600,
			Expiration:  1704931200,
			Inception:   1703116800,
			KeyTag:      45269,
			SignerName:  "ipb.pt",
			Signature:   "e+ACsJVlX+uZTbt0B2dXJQmbjUkBBXwt1tb0W6KF5A5lLwKtmrpamSIqoNK3zJcwlGKRL1wkpUe4ZKakrwrumI4lErSrRIjP0zcH3tRw9ZWm5wmwW5HSr7XBN0nkNvqLEM7d7a61qTE3rqxcddgefSKTaYFuJVAgepXkGvIV5p0=",
		},
		RawResponse: response,
	}
	r := &AAAAResponse{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse AAAA record: %v", err)
	}
	aaaaRecord, ok := result.(*AAAAResponse)
	if !ok {
		t.Fatalf("Result is not a *AAAAResponse")
	}

	if !aaaaRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", aaaaRecord, expected)
	}
}

func TestNewAAAARecordNoDNSSEC(t *testing.T) {
	response := unsignedAAAAResponse
	expected := &AAAAResponse{
		Records: []AAAARecord{
			{
				IPv6:        "2001:690:22c0:201::4",
				OriginalTTL: 1800,
			},
		},
		Validated:   false,
		RRSIG:       nil,
		RawResponse: response,
	}
	r := &AAAAResponse{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse AAAA record: %v", err)
	}
	aaaaRecord, ok := result.(*AAAAResponse)
	if !ok {
		t.Fatalf("Result is not a *AAAAResponse")
	}

	if !aaaaRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", aaaaRecord, expected)
	}
}

func TestNewAAAARecordNoIPv6(t *testing.T) {
	response := badAAAAResponse
	r := &AAAAResponse{}
	dsRecord, err := r.Parse(response)
	if err == nil {
		t.Fatalf("Expected resolution failed error, got nil")
	}
	if dsRecord != nil {
		t.Fatalf("Expected nil AAAA record, got %+v", dsRecord)
	}

	if !strings.Contains(err.Error(), "resolution failed") {
		t.Errorf("Expected error to contain 'resolution failed', got: %v", err)
	}
}

const goodAAAAResponse = `; fully validated
ipb.pt.                 3600    IN      AAAA    2001:690:22c0:201::4
ipb.pt.                 3600    IN      RRSIG   AAAA 7 2 3600 20240111000000 20231221000000 45269 ipb.pt. e+ACsJVlX+uZTbt0B2dXJQmbjUkBBXwt1tb0W6KF5A5lLwKtmrpamSIq oNK3zJcwlGKRL1wkpUe4ZKakrwrumI4lErSrRIjP0zcH3tRw9ZWm5wmw W5HSr7XBN0nkNvqLEM7d7a61qTE3rqxcddgefSKTaYFuJVAgepXkGvIV 5p0=`

const badAAAAResponse = `;; resolution failed: ncache nxrrset
; negative response, unsigned answer
; ipvc.pt.              1800    IN      \-AAAA  ;-$NXRRSET
; ipvc.pt. SOA ns3.ipvc.pt. si.ipvc.pt. 2023121969 28800 7200 1209600 86400`

const unsignedAAAAResponse = `; unsigned answer
ipb.pt.                 1800    IN      AAAA    2001:690:22c0:201::4`
