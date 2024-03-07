package dnsrecords

import (
	"testing"
)

func TestNewRRSIGRecord(t *testing.T) {
	testLine := "uminho.pt.              14400   IN      RRSIG   SOA 5 2 14400 20240114000002 20231215000002 51330 uminho.pt. ZysOlFWuqRItdxt59+BbS+iMTyrM35fu1r1Lgds/ooCFwKORRkmnpmZo Fa2qg8E1lxvEkmVjh1AkXMi+d3Lnls8JhO0MDe6OFrRsRhQg170D5sWJ 3nleX0In72eBZDRl3zOO7c8z+KE5S+/K+DVvQ6SDcj2D6EqYWUss9NsS 2Mk="
	expected := &RRSIGRecord{
		TypeCovered: "SOA",
		Algorithm:   5,
		Labels:      2,
		OriginalTTL: 14400,
		Expiration:  1705190402,
		Inception:   1702598402,
		KeyTag:      51330,
		SignerName:  "uminho.pt",
		Signature:   "ZysOlFWuqRItdxt59+BbS+iMTyrM35fu1r1Lgds/ooCFwKORRkmnpmZoFa2qg8E1lxvEkmVjh1AkXMi+d3Lnls8JhO0MDe6OFrRsRhQg170D5sWJ3nleX0In72eBZDRl3zOO7c8z+KE5S+/K+DVvQ6SDcj2D6EqYWUss9NsS2Mk=",
	}
	r := &RRSIGRecord{}
	rrsigRecordResult, err := r.Parse(testLine)
	if err != nil {
		t.Fatalf("Failed to parse RRSIG record: %v", err)
	}
	rrsigRecord, ok := rrsigRecordResult.(*RRSIGRecord)
	if !ok {
		t.Fatalf("Result is not a *RRSIGRecord")
	}

	if !rrsigRecord.Compare(expected) {
		t.Errorf("Parsed record %+v does not match expected %+v", rrsigRecord, expected)
	}
}

func compareRRSIGRecords(a, b *RRSIGRecord) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return a.TypeCovered == b.TypeCovered &&
		a.Algorithm == b.Algorithm &&
		a.Labels == b.Labels &&
		a.OriginalTTL == b.OriginalTTL &&
		a.Expiration == b.Expiration &&
		a.Inception == b.Inception &&
		a.KeyTag == b.KeyTag &&
		a.SignerName == b.SignerName &&
		a.Signature == b.Signature
}
