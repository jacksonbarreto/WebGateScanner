package dnsrecords

import (
	"strings"
	"testing"
)

func TestNewSOARecord(t *testing.T) {
	response := `; fully validated
uminho.pt.              14400   IN      SOA     dns.uminho.pt. servicos.scom.uminho.pt. 2023121501 14400 7200 1209600 300 
uminho.pt.              14400   IN      RRSIG   SOA 5 2 14400 20240114000002 20231215000002 51330 uminho.pt. ZysOlFWuqRItdxt59+BbS+iMTyrM35fu1r1Lgds/ooCFwKORRkmnpmZo Fa2qg8E1lxvEkmVjh1AkXMi+d3Lnls8JhO0MDe6OFrRsRhQg170D5sWJ 3nleX0In72eBZDRl3zOO7c8z+KE5S+/K+DVvQ6SDcj2D6EqYWUss9NsS 2Mk=`

	expected := &SOARecord{
		PrimaryNS: "dns.uminho.pt",
		Contact:   "servicos@scom.uminho.pt",
		Serial:    2023121501,
		Refresh:   14400,
		Retry:     7200,
		Expire:    1209600,
		Minimum:   300,
		Validated: true,
		RRSIG: &RRSIGRecord{
			TypeCovered: "SOA",
			Algorithm:   5,
			Labels:      2,
			OriginalTTL: 14400,
			Expiration:  1705190402,
			Inception:   1702598402,
			KeyTag:      51330,
			SignerName:  "uminho.pt",
			Signature:   "ZysOlFWuqRItdxt59+BbS+iMTyrM35fu1r1Lgds/ooCFwKORRkmnpmZoFa2qg8E1lxvEkmVjh1AkXMi+d3Lnls8JhO0MDe6OFrRsRhQg170D5sWJ3nleX0In72eBZDRl3zOO7c8z+KE5S+/K+DVvQ6SDcj2D6EqYWUss9NsS2Mk=",
		},
		RawResponse: response,
	}
	r := &SOARecord{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse SOA record: %v", err)
	}
	soaRecord, ok := result.(*SOARecord)
	if !ok {
		t.Fatalf("Result is not a *SOARecord")
	}

	if !soaRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", soaRecord, expected)
	}
}

func TestNewSOARecordNoDNSSEC(t *testing.T) {
	response := `; unsigned answer
ipvc.pt.                21600   IN      SOA     ns3.ipvc.pt. si.ipvc.pt. 2023121969 28800 7200 1209600 86400`

	expected := &SOARecord{
		PrimaryNS:   "ns3.ipvc.pt",
		Contact:     "si@ipvc.pt",
		Serial:      2023121969,
		Refresh:     28800,
		Retry:       7200,
		Expire:      1209600,
		Minimum:     86400,
		Validated:   false,
		RRSIG:       nil,
		RawResponse: response,
	}
	r := &SOARecord{}
	result, err := r.Parse(response)
	if err != nil {
		t.Fatalf("Failed to parse SOA record without DNSSEC: %v", err)
	}
	soaRecord, ok := result.(*SOARecord)
	if !ok {
		t.Fatalf("Result is not a *SOARecord")
	}

	if !soaRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", soaRecord, expected)
	}
}

func TestNewSOARecordResolutionFailed(t *testing.T) {
	response := `;; resolution failed: ncache nxdomain
; negative response, fully validated
; uminhok.pt.           300     IN      \-DS    ;-$NXDOMAIN
; pt. SOA curiosity.dns.pt. request.dns.pt. 2023122726 21600 7200 2592000 300
; pt. RRSIG SOA ...
; 6EAFAT67EVGJT80C6SMVTD55MDT4THVH.pt. RRSIG NSEC3 ...
; 6EAFAT67EVGJT80C6SMVTD55MDT4THVH.pt. NSEC3 1 1 10 D115 6EBGGCH2JDDDPO0R36G469S3H8OP9AO6 NS DS RRSIG
; GVEN2I02PUJAAEC8FKFQRRC0S0HAQENM.pt. RRSIG NSEC3 ...
; GVEN2I02PUJAAEC8FKFQRRC0S0HAQENM.pt. NSEC3 1 1 10 D115 GVI4V48Q80F5BGSHLINQEUUMK45JME6U NS DS RRSIG
; PCTPFDAMBNVNP7A29HJ4PLCNTIHBFKBK.pt. RRSIG NSEC3 ...
; PCTPFDAMBNVNP7A29HJ4PLCNTIHBFKBK.pt. NSEC3 1 1 10 D115 PD356TUO7HSQBQ1L6QPTCDRI8T10BR5P NS SOA RRSIG DNSKEY NSEC3PARAMRecord`

	r := &SOARecord{}
	soaRecord, err := r.Parse(response)
	if err == nil {
		t.Fatalf("Expected resolution failed error, got nil")
	}

	if soaRecord != nil {
		t.Errorf("Expected nil SOA record, got: %+v", soaRecord)
	}

	if !strings.Contains(err.Error(), "resolution failed") {
		t.Errorf("Expected error to contain 'resolution failed', got: %v", err)
	}
}
