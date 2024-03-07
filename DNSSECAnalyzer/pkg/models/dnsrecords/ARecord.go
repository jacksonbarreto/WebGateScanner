package dnsrecords

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ARecord represents a single A (Address) resource record in the Domain Name System (DNS).
// An A record maps a domain name to an IPv4 address, enabling clients to locate servers
// and other resources on the Internet.
//
// Fields:
//
//	IPv4: A string representing the IPv4 address associated with the domain name.
//	      The address is in dotted-decimal notation (e.g., "192.0.2.1").
//
//	OriginalTTL: An unsigned 32-bit integer indicating the original time-to-live (TTL) value
//	             of the A record. This value specifies the duration in seconds that the record
//	             may be cached before it should be discarded or refreshed.
type ARecord struct {
	IPv4        string
	OriginalTTL uint32
}

// String returns a formatted string representation of the ARecord.
// This method implements the fmt.Stringer interface for pretty-printing the record.
func (r *ARecord) String() string {
	return fmt.Sprintf(
		"ARecord:\n"+
			"  IPv4 Address: %s\n"+
			"  Original TTL: %d seconds\n",
		r.IPv4,
		r.OriginalTTL,
	)
}

// AResponse represents the complete response for an A record query.
// It includes a collection of A records, the validation status of the response,
// any associated RRSIG record for DNSSEC validation, and the raw response received
// from the DNS server. This struct is particularly useful when dealing with
// responses that include multiple A records for a single domain name.
//
// Fields:
//
//	Records: A slice of ARecord structs, each representing an individual A record.
//	         Multiple A records may be present if a domain name resolves to multiple
//	         IPv4 addresses.
//
//	Validated: A boolean flag indicating whether the A records have been validated
//	           using DNSSEC validation procedures. True if validated, false otherwise.
//
//	RRSIG: A pointer to an RRSIGRecord struct that contains the DNSSEC signature for this
//	       A record set. This field is nil if DNSSEC is not used or if the record is not signed.
//
//	RawResponse: A string containing the raw textual response received from the DNS server,
//	             which can be useful for logging, debugging, or other diagnostic purposes.
type AResponse struct {
	Records     []ARecord
	Validated   bool
	RRSIG       *RRSIGRecord
	RawResponse string
}

// Parse parses a raw DNS response string and creates a new AResponse struct.
// This function is designed to work with the output of the 'delv' command-line tool
// for A queries. The A query is used to resolve a domain name to its IPv4 address.
// The parsed information from the 'delv' response is used to populate an AResponse struct,
// which represents a structured interpretation of the A records and associated data.
//
// Parameters:
//
//	response: A string containing the raw textual response from the 'delv' command-line tool.
//	          This response should be the result of an A query for a specific domain.
//	          The response string is expected to include the A records, along with
//	          any associated RRSIG records and other relevant DNS information.
//
// Return Value:
//
//	*AResponse: A pointer to an AResponse struct that contains the parsed A records,
//	            the validation status, the associated RRSIG record (if available), and the raw response.
//	            This struct provides a structured representation of the IPv4 addresses
//	            and associated data extracted from the 'delv' response.
//
//	error: An error object that indicates any issues encountered during the parsing of the
//	       response string. If the parsing is successful, the error is nil. If parsing fails,
//	       the error provides details about the cause of the failure.
//
// Example Usage:
//
//	aResponse, err := newARecord(rawDelvResponse)
//	if err != nil {
//	    // Handle error
//	}
//	// Use aResponse for DNS queries or other purposes
//
// Note:
//
//	This function is specifically designed to parse the output of the 'delv' command-line tool,
//	which is commonly used for DNS diagnostics and troubleshooting. The function assumes that the input
//	string is in the format provided by 'delv' and may not work correctly with responses from
//	other tools or in different formats.
func (r *AResponse) Parse(response string) (DNSRecordResult, error) {
	lines := strings.Split(response, "\n")
	if strings.Contains(response, "resolution failed") {
		return nil, fmt.Errorf("resolution failed: %s", lines[0])
	}
	r.RawResponse = response
	aRegex := regexp.MustCompile(`\bIN\s+A\b`)
	rrsigRegex := regexp.MustCompile(`\bRRSIG\s+A\b`)

	for _, line := range lines {
		if strings.HasPrefix(line, "; fully validated") {
			r.Validated = true
		} else if strings.HasPrefix(line, "; unsigned answer") {
			r.Validated = false
		} else if aRegex.MatchString(line) {
			aRecord := &ARecord{}
			parts := strings.Fields(line)
			if len(parts) < 5 {
				return nil, fmt.Errorf("invalid A r: %s", line)
			}
			ttl, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid TTL '%s' in A r: %v", parts[1], err)
			}
			aRecord.OriginalTTL = uint32(int(ttl))

			aRecord.IPv4 = parts[4]
			r.Records = append(r.Records, *aRecord)

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

// Compare checks the equality between two instances of ARecord.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *ARecord) Compare(b *ARecord) bool {
	return r.IPv4 == b.IPv4
}

// Compare checks the equality between two instances of AResponse.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *AResponse) Compare(b *AResponse) bool {
	if len(r.Records) != len(b.Records) {
		return false
	}
	for i := range r.Records {
		if !r.Records[i].Compare(&b.Records[i]) {
			return false
		}
	}
	return r.Validated == b.Validated &&
		r.RRSIG.Compare(b.RRSIG) &&
		r.RawResponse == b.RawResponse
}

// String returns a formatted string representation of the AResponse.
// This method implements the fmt.Stringer interface for pretty-printing the response.
func (r *AResponse) String() string {
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
		"AResponse:\n"+
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
