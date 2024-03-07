package dnsrecords

import (
	"testing"
)

func TestNewARecordOK(t *testing.T) {
	response := goodAResponse
	expected := &AResponse{
		Records: []ARecord{
			{
				IPv4:        "193.136.195.224",
				OriginalTTL: 21600,
			},
		},
		Validated: true,
		RRSIG: &RRSIGRecord{
			TypeCovered: "A",
			Algorithm:   7,
			Labels:      2,
			OriginalTTL: 86400,
			Expiration:  1704931200,
			Inception:   1703116800,
			KeyTag:      45269,
			SignerName:  "ipb.pt",
			Signature:   "I3qvkVcnFSqPHb4QrSFWCphRQSqOqLi1LM8gQdBtMGiWdPvBhRNI5Kxm+xgX/F443DIVuzFWbIhPYNnInT/OgWHPUF+UkbtpYopS0lOD8mJJ5e26PFQb65Jw9rgJAEomjA3dQa6D67mut7KtFgIapUtXOVUYLET9NJwv1Q2H4gs=",
		},
		RawResponse: response,
	}
	r := &AResponse{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse A record: %v", err)
	}

	aRecord, ok := result.(*AResponse)
	if !ok {
		t.Fatalf("Result is not a *AResponse")
	}

	if !aRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", aRecord, expected)
	}
}

func TestNewARecordNoDNSSEC(t *testing.T) {
	response := unsignedAResponse

	expected := &AResponse{
		Records: []ARecord{
			{
				IPv4:        "193.136.58.74",
				OriginalTTL: 600,
			},
		},
		Validated:   false,
		RRSIG:       nil,
		RawResponse: response,
	}
	r := &AResponse{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse A record: %v", err)
	}

	aRecord, ok := result.(*AResponse)
	if !ok {
		t.Fatalf("Result is not a *AResponse")
	}

	if !aRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", aRecord, expected)
	}
}

const goodAResponse = `; fully validated
ipb.pt.                 21600   IN      A       193.136.195.224
ipb.pt.                 21600   IN      RRSIG   A 7 2 86400 20240111000000 20231221000000 45269 ipb.pt. I3qvkVcnFSqPHb4QrSFWCphRQSqOqLi1LM8gQdBtMGiWdPvBhRNI5Kxm +xgX/F443DIVuzFWbIhPYNnInT/OgWHPUF+UkbtpYopS0lOD8mJJ5e26 PFQb65Jw9rgJAEomjA3dQa6D67mut7KtFgIapUtXOVUYLET9NJwv1Q2H 4gs=`

const unsignedAResponse = `; unsigned answer
ipp.pt.                 600     IN      A       193.136.58.74`
