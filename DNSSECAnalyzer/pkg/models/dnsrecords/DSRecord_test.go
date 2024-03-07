package dnsrecords

import (
	"strings"
	"testing"
)

func TestNewDSRecordOK(t *testing.T) {
	response := goodResponse
	expected := &DSResponse{
		Records: []DSRecord{
			{
				KeyTag:     36028,
				Algorithm:  5,
				DigestType: 1,
				Digest:     "DF93A5A17FC9091F076137A6837C61DE997C80D6",
			},
			{
				KeyTag:     36028,
				Algorithm:  5,
				DigestType: 2,
				Digest:     "F1FB0C99D1FA5342D3A400F6BCE704C9015C819CF5C037131F68C87EC96D9AA6",
			},
		},
		Validated: true,
		RRSIG: &RRSIGRecord{
			TypeCovered: "DS",
			Algorithm:   13,
			Labels:      2,
			OriginalTTL: 7200,
			Expiration:  1704540034,
			Inception:   1703676034,
			KeyTag:      30640,
			SignerName:  "pt",
			Signature:   "fOMoycB+AmzBpJNdwgzqSXfZAt1ktZ39nzRr4RChNQFnhY3a9mjXOinyoe+hzNWarx4w9wCdyLZP4Wu9zprowQ==",
		},
		RawResponse: response,
	}

	dsResponse := DSResponse{}
	dsRecordResult, err := dsResponse.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse DS record: %v", err)
	}

	dsRecord, ok := dsRecordResult.(*DSResponse)
	if !ok {
		t.Fatalf("Result is not a *DSResponse")
	}

	if !dsRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", dsRecord, expected)
	}
}

func TestNewDSRecordNoDNSSEC(t *testing.T) {
	response := badResponse
	dsResponse := DSResponse{}
	dsRecord, err := dsResponse.Parse(response)
	if err == nil {
		t.Fatalf("Expected resolution failed error, got nil")
	}
	if dsRecord != nil {
		t.Fatalf("Expected nil DS record, got %+v", dsRecord)
	}

	if !strings.Contains(err.Error(), "resolution failed") {
		t.Errorf("Expected error to contain 'resolution failed', got: %v", err)
	}
}

const goodResponse = `; fully validated
uminho.pt.              7200    IN      DS      36028 5 1 DF93A5A17FC9091F076137A6837C61DE997C80D6
uminho.pt.              7200    IN      DS      36028 5 2 F1FB0C99D1FA5342D3A400F6BCE704C9015C819CF5C037131F68C87E C96D9AA6
uminho.pt.              7200    IN      RRSIG   DS 13 2 7200 20240106112034 20231227112034 30640 pt. fOMoycB+AmzBpJNdwgzqSXfZAt1ktZ39nzRr4RChNQFnhY3a9mjXOiny oe+hzNWarx4w9wCdyLZP4Wu9zprowQ==`

const badResponse = `;; resolution failed: ncache nxrrset
; negative response, fully validated
; ipp.pt.                       300     IN      \-DS    ;-$NXRRSET
; pt. SOA curiosity.dns.pt. request.dns.pt. 2023122730 21600 7200 2592000 300
; pt. RRSIG SOA ...
; pctpfdambnvnp7a29hj4plcntihbfkbk.pt. RRSIG NSEC3 ...
; pctpfdambnvnp7a29hj4plcntihbfkbk.pt. NSEC3 1 1 10 D115 PD356TUO7HSQBQ1L6QPTCDRI8T10BR5P NS SOA RRSIG DNSKEY NSEC3PARAMRecord
; r9ka1k6dieu2jtienhhecqpvo7ond32a.pt. RRSIG NSEC3 ...
; r9ka1k6dieu2jtienhhecqpvo7ond32a.pt. NSEC3 1 1 10 D115 R9M3MK6FQ0UFTJSN6LI9FS0CPAELHCKK NS DS RRSIG`
