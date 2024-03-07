package dnsrecords

import (
	"strings"
	"testing"
)

func TestNewNSECRecordGoodResponse(t *testing.T) {
	response := goodNsecResponse
	expected := &NSECRecord{
		TTL:            86400,
		NextDomainName: "25anos.ipb.pt.",
		Types:          "A;NS;SOA;MX;TXT;AAAA;NAPTR;RRSIG;NSEC;DNSKEY;NSEC3PARAM;CAA",
		Validated:      true,
		RRSIG: &RRSIGRecord{
			TypeCovered: "NSEC",
			Algorithm:   7,
			Labels:      2,
			OriginalTTL: 86400,
			Expiration:  1704931200,
			Inception:   1703116800,
			KeyTag:      45269,
			SignerName:  "ipb.pt",
			Signature:   "XhwuwEZiiohAhkTOMuk5+dyBD/yhJatUXHvIArt05t8FA7YYGJGHuwZM24cfumpHxXBgVlRWTuYnFlJbmaPBtqDoYQs4txw0UsIuFXo1lAdK713OMUp4lWlkf04hJC4LWRiDvZg2k/glXSo077O3Fyg5VYjU/YpTNyR4DbgJDGo=",
		},
		RawResponse: response,
	}
	r := &NSECRecord{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse NSEC record: %v", err)
	}
	nsecRecord, ok := result.(*NSECRecord)
	if !ok {
		t.Fatalf("Result is not a *NSECRecord")
	}

	if !nsecRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", nsecRecord, expected)
	}
}

func TestNewNSECRecordBadResponse(t *testing.T) {
	response := badNsecResponse
	r := &NSECRecord{}
	result, err := r.Parse(response)
	if err == nil {
		t.Fatalf("Expected resolution failed error, got nil")
	}
	nsecRecord, ok := result.(*NSECRecord)
	if ok {
		t.Fatalf("Expected nil NSEC record, got %+v", nsecRecord)
	}
	if nsecRecord != nil {
		t.Fatalf("Expected nil NSEC response, got %+v", nsecRecord)
	}

	if !strings.Contains(err.Error(), "resolution failed") {
		t.Errorf("Expected error to contain 'resolution failed', got: %v", err)
	}
}

const goodNsecResponse = `; fully validated
ipb.pt.                 86400   IN      NSEC    25anos.ipb.pt. A NS SOA MX TXT AAAA NAPTR RRSIG NSEC DNSKEY NSEC3PARAM CAA
ipb.pt.                 86400   IN      RRSIG   NSEC 7 2 86400 20240111000000 20231221000000 45269 ipb.pt. XhwuwEZiiohAhkTOMuk5+dyBD/yhJatUXHvIArt05t8FA7YYGJGHuwZM 24cfumpHxXBgVlRWTuYnFlJbmaPBtqDoYQs4txw0UsIuFXo1lAdK713O MUp4lWlkf04hJC4LWRiDvZg2k/glXSo077O3Fyg5VYjU/YpTNyR4DbgJ DGo=`

const badNsecResponse = `;; resolution failed: ncache nxrrset
; negative response, fully validated
; nl.                   600     IN      \-NSEC  ;-$NXRRSET
; nl. SOA ns1.dns.nl. hostmaster.domain-registry.nl. 2023122832 3600 600 2419200 600
; nl. RRSIG SOA ...
; k36vo59bkum4osckkrd8tvibdgr0njbc.nl. RRSIG NSEC3 ...
; k36vo59bkum4osckkrd8tvibdgr0njbc.nl. NSEC3 1 0 0 - K36VONMLM2T8IF3G8P5AV864OHLTB7K7 NS SOA TXT RRSIG DNSKEY NSEC3PARAM`
