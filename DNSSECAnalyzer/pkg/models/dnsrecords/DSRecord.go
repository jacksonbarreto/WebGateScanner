package dnsrecords

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DSRecord represents a single DNSSEC Delegation Signer (DS) record.
// A DS record is used in DNSSEC to link a child zone to a parent zone,
// enabling the validation of DNSSEC-signed records in the child zone.
//
// Fields:
//
//	KeyTag: A 16-bit identifier of the DNSKEY record in the child zone
//	        that is used to sign the zone's DNS records. It is used to efficiently
//	        locate the correct DNSKEY record in the child zone.
//
//	Algorithm: An 8-bit integer identifying the cryptographic algorithm
//	           used to create the signature in the DNSKEY record. The value corresponds
//	           to IANA DNSSEC Algorithm Identifiers.
//
//	DigestType: An 8-bit integer representing the type of digest
//	            that is used to create a hash of the DNSKEY record. The value
//	            corresponds to IANA DS Record Digest Types.
//
//	Digest: A string representing the hexadecimal value of the digest
//	        (hash) of the DNSKEY record. The digest is calculated using the method
//	        specified in the DigestType field.
type DSRecord struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
}

// String returns a formatted string representation of the DSRecord.
// This method provides a readable view of the DS record's key tag, algorithm, digest type, and digest.
func (r *DSRecord) String() string {
	if r == nil {
		return "<null>"
	}

	return fmt.Sprintf(
		"DSRecord:\n"+
			"  Key Tag: %d\n"+
			"  Algorithm: %d\n"+
			"  Digest Type: %d\n"+
			"  Digest: %s\n",
		r.KeyTag,
		r.Algorithm,
		r.DigestType,
		r.Digest,
	)
}

// DSResponse represents a complete response for a DNSSEC DS record query.
// This includes potentially multiple DS records, a flag indicating whether
// the response was validated, the RRSIG record for the response, and the
// raw response received from the DNS server.
//
// Fields:
//
//	Records: A slice of DSRecord, each representing an individual
//	         Delegation Signer record. Multiple DS records may be included to
//	         support different algorithms or keys.
//
//	Validated: A boolean flag indicating whether the DS records
//	           in the response have been validated using DNSSEC validation procedures.
//
//	RRSIG: A pointer to an RRSIGRecord, which contains the DNSSEC
//	       signature for this DS record set. This field may be nil if the
//	       response does not include a signature or if DNSSEC is not enabled.
//
//	RawResponse: A string containing the raw textual response received
//	             from the DNS server. It may be used for logging, debugging, or
//	             other diagnostic purposes.
type DSResponse struct {
	Records     []DSRecord
	Validated   bool
	RRSIG       *RRSIGRecord
	RawResponse string
}

// Parse creates a new DSResponse struct from a raw DNS response string.
// A DSResponse struct is populated with the parsed information from the DNS response,
// typically obtained from a DNSSEC DS record query using the 'delv' command-line tool.
//
// Parameters:
//
//	response: A string containing the raw textual response from the 'delv' command-line tool.
//	          This response should be the result of a query for DS records for a specific domain.
//	          The response string is expected to include one or more DS records, along with
//	          any associated RRSIG records and other relevant DNSSEC information.
//
// Return Value:
//
//	*DSResponse: A pointer to a DSResponse struct that contains the parsed DS records,
//	             validation status, associated RRSIG record (if available), and the raw response.
//	             This struct provides a structured representation of the DNSSEC DS records
//	             and associated data.
//
//	error: An error object that indicates any issues encountered during the parsing of the
//	       response string. If the parsing is successful, the error is nil. If parsing fails,
//	       the error provides details about the cause of the failure.
//
// Example Usage:
//
//	dsResponse, err := Parse(rawDelvResponse)
//	if err != nil {
//	    // Handle error
//	}
//	// Use dsResponse for DNSSEC validation or other purposes
//
// Note:
//
//	This function is designed to parse the output of the 'delv' command-line tool,
//	which is used for DNSSEC troubleshooting and diagnostics. The function assumes
//	that the input string is in the format provided by 'delv', and it may not work
//	correctly with responses from other tools or in different formats.
func (r *DSResponse) Parse(response string) (DNSRecordResult, error) {
	lines := strings.Split(response, "\n")
	if strings.Contains(response, "resolution failed") {
		return nil, fmt.Errorf("resolution failed: %s", lines[0])
	}
	r.RawResponse = response
	dsRegex := regexp.MustCompile(`\bIN\s+DS\b`)
	rrsigRegex := regexp.MustCompile(`\bRRSIG\s+DS\b`)

	for _, line := range lines {
		if strings.HasPrefix(line, "; fully validated") {
			r.Validated = true
		} else if strings.HasPrefix(line, "; unsigned answer") {
			r.Validated = false
		} else if dsRegex.MatchString(line) {
			dsRecord := &DSRecord{}
			parts := strings.Fields(line)
			if len(parts) < 8 {
				return nil, fmt.Errorf("invalid DS r format: %s", line)
			}

			keyTag, err := strconv.ParseUint(parts[4], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid key tag '%s' in DS r: %v", parts[4], err)
			}
			dsRecord.KeyTag = uint16(keyTag)

			algorithm, err := strconv.ParseUint(parts[5], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid algorithm '%s' in DS r: %v", parts[5], err)
			}
			dsRecord.Algorithm = uint8(algorithm)

			digestType, err := strconv.ParseUint(parts[6], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid digest type '%s' in DS r: %v", parts[6], err)
			}
			dsRecord.DigestType = uint8(digestType)

			dsRecord.Digest = strings.Join(parts[7:], "")

			r.Records = append(r.Records, *dsRecord)
		} else if rrsigRegex.MatchString(line) {
			rrsigParser := &RRSIGRecord{}
			rrsigRecord, err := rrsigParser.Parse(line)
			if err != nil {
				return nil, err
			}
			r.RRSIG = rrsigRecord.(*RRSIGRecord)
		}
	}
	return r, nil
}

// Compare checks the equality between two instances of DSRecord.
// This function is useful for testing and validation purposes, where it is necessary
// to compare two DS records to verify if they have the same values.
//
// Parameters:
// - b: A reference to another instance of DSRecord for comparison.
//
// Returns:
//   - bool: Returns true if all properties of 'a' and 'b' are equal;
//     otherwise, returns false.
func (r *DSRecord) Compare(b *DSRecord) bool {
	return r.KeyTag == b.KeyTag &&
		r.Algorithm == b.Algorithm &&
		r.DigestType == b.DigestType &&
		r.Digest == b.Digest
}

// Compare checks the equality between two instances of DSResponse.
// This function is useful for testing and validation purposes, where it is necessary
// to compare two DS responses to verify if they contain the same records,
// validation status, RRSIG records, and raw DNS response.
//
// Parameters:
// - b: A reference to another instance of DSResponse for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     including the individual DS records, validation status, RRSIG records,
//     and the raw response; otherwise, returns false.
func (r *DSResponse) Compare(b *DSResponse) bool {
	if len(r.Records) != len(b.Records) {
		return false
	}
	for i := range r.Records {
		if !r.Records[i].Compare(&b.Records[i]) {
			return false
		}
	}

	if r.RRSIG != nil && b.RRSIG != nil {
		if !r.RRSIG.Compare(b.RRSIG) {
			return false
		}
	} else if r.RRSIG != b.RRSIG {
		return false
	}

	return r.Validated == b.Validated && r.RawResponse == b.RawResponse
}

// String returns a formatted string representation of the DSResponse.
// It provides a human-readable view of the response, including the DS records, validation status, and raw response.
func (r *DSResponse) String() string {
	if r == nil {
		return "<null>"
	}

	var recordsStr []string
	for _, record := range r.Records {
		recordsStr = append(recordsStr, record.String())
	}

	validatedStr := "No"
	if r.Validated {
		validatedStr = "Yes"
	}

	rrsigStr := "<null>"
	if r.RRSIG != nil {
		rrsigStr = r.RRSIG.String()
	}

	return fmt.Sprintf(
		"DSResponse:\n"+
			"  Records:\n    %s\n"+
			"  Validated: %s\n"+
			"  RRSIG: %s\n"+
			"  Raw Response: %s\n",
		strings.Join(recordsStr, "\n    "),
		validatedStr,
		rrsigStr,
		r.RawResponse,
	)
}
