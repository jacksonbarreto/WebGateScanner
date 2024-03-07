package dnsrecords

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RRSIGRecord represents a DNSSEC Resource Record Signature (RRSIG). It includes metadata
// about the digital signature used to secure a specific set of DNS records (RRset).
// Fields:
// TypeCovered: Type of the RRset that this RRSIG record covers (e.g., SOA, DS, DNSKEY).
// Algorithm: Numerical identifier of the cryptographic algorithm used for the signature, as per RFC 4034.
// Labels: Number of labels in the original RRSIG RR owner name.
// OriginalTTL: Original TTL of the covered RRset, as it appears in the authoritative zone.
// Expiration: Expiration date of the signature, represented as a UNIX timestamp.
// Inception: Inception date of the signature, also as a UNIX timestamp.
// KeyTag: Identifier of the DNSKEY record that validates this signature.
// SignerName: Domain name of the signer (entity that generated the signature).
// Signature: Actual digital signature in base64 encoding.
type RRSIGRecord struct {
	TypeCovered string
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   string
}

// Parse extracts information from a raw textual representation of an RRSIG record
// and populates the fields of the RRSIGRecord struct. This method is designed to
// parse a single line of RRSIG record data, typically obtained from a DNS response
// or diagnostic tool output (e.g., 'delv').
//
// Parameters:
//
//	rrsigLine: A string representing a single line of RRSIG record data.
//	           The format of this line should follow the standard RRSIG record format,
//	           containing fields such as Type Covered, Algorithm, Labels, Original TTL,
//	           Expiration, Inception, Key Tag, Signer's Name, and Signature.
//
// Returns:
//
//	DNSRecordResult: A struct that implements the DNSRecordResult interface, specifically
//	                 an *RRSIGRecord struct, populated with the parsed data from the RRSIG line.
//	                 This return type allows for flexibility in handling different DNS record types.
//
//	error: An error object that indicates any issues encountered during the parsing of the RRSIG line.
//	       If the parsing is successful, the error is nil. If parsing fails due to incorrect format,
//	       invalid values, or any other reason, the error provides details about the cause of the failure.
//
// Example Usage:
//
//	// Assume 'rrsigLine' is a string containing an RRSIG record
//	rrsigRecord, err := (&RRSIGRecord{}).Parse(rrsigLine)
//	if err != nil {
//	    // Handle error
//	}
//	// Use rrsigRecord for DNSSEC validation or other purposes
//
// Note:
//
//   - The method expects the input string to be in a specific format, closely aligned with the standard
//     RRSIG record representation. Deviations from this format may lead to parsing errors.
//   - This method is particularly useful when dealing with DNS diagnostic tools' outputs or raw DNS responses
//     where RRSIG records are presented in textual format.
func (r *RRSIGRecord) Parse(rrsigLine string) (DNSRecordResult, error) {
	parts := strings.Fields(rrsigLine)
	if len(parts) < 13 {
		return nil, errors.New("invalid RRSIG record format")
	}

	algorithm, err := strconv.ParseUint(parts[5], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid algorithm value '%s' in RRSIG record: %v", parts[5], err)
	}

	labels, err := strconv.ParseUint(parts[6], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid labels value '%s' in RRSIG record: %v", parts[6], err)
	}

	originalTTL, err := strconv.ParseUint(parts[7], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid original TTL value '%s' in RRSIG record: %v", parts[7], err)
	}

	expiration, err := parseTime(parts[8])
	if err != nil {
		return nil, fmt.Errorf("invalid expiration time value '%s' in RRSIG record: %v", parts[8], err)
	}

	inception, err := parseTime(parts[9])
	if err != nil {
		return nil, fmt.Errorf("invalid inception time value '%s' in RRSIG record: %v", parts[9], err)
	}

	keyTag, err := strconv.ParseUint(parts[10], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid key tag value '%s' in RRSIG record: %v", parts[10], err)
	}

	signerName := strings.TrimSuffix(parts[11], ".")
	signature := strings.Join(parts[12:], "")

	return &RRSIGRecord{
		TypeCovered: parts[4],
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OriginalTTL: uint32(originalTTL),
		Expiration:  uint32(expiration),
		Inception:   uint32(inception),
		KeyTag:      uint16(keyTag),
		SignerName:  signerName,
		Signature:   signature,
	}, nil
}

// DateFormat follows the Go standard layout for time parsing (YearMonthDayHourMinuteSecond), which uses the reference date: Mon Jan 2 15:04:05 MST 2006.
const DateFormat = "20060102150405"

func parseTime(timeStr string) (int64, error) {
	t, err := time.Parse(DateFormat, timeStr)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// Compare checks the equality between two instances of RRSIGRecord.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *RRSIGRecord) Compare(b *RRSIGRecord) bool {
	if r == nil && b == nil {
		return true
	}

	if r == nil || b == nil {
		return false
	}

	return r.TypeCovered == b.TypeCovered &&
		r.Algorithm == b.Algorithm &&
		r.Labels == b.Labels &&
		r.OriginalTTL == b.OriginalTTL &&
		r.Expiration == b.Expiration &&
		r.Inception == b.Inception &&
		r.KeyTag == b.KeyTag &&
		r.SignerName == b.SignerName &&
		r.Signature == b.Signature
}

// String returns a formatted string representation of the RRSIGRecord.
// This method implements the fmt.Stringer interface so that the RRSIGRecord
// is printed in a human-readable form, rather than just displaying the pointer.
func (r *RRSIGRecord) String() string {
	return fmt.Sprintf(
		"RRSIGRecord:\n"+
			"  Type Covered: %s\n"+
			"  Algorithm: %d\n"+
			"  Labels: %d\n"+
			"  Original TTL: %d\n"+
			"  Expiration: %s\n"+
			"  Inception: %s\n"+
			"  Key Tag: %d\n"+
			"  Signer Name: %s\n"+
			"  Signature: %s\n",
		r.TypeCovered,
		r.Algorithm,
		r.Labels,
		r.OriginalTTL,
		time.Unix(int64(r.Expiration), 0).Format(time.RFC3339),
		time.Unix(int64(r.Inception), 0).Format(time.RFC3339),
		r.KeyTag,
		r.SignerName,
		r.Signature,
	)
}
