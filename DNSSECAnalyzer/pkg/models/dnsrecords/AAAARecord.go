package dnsrecords

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AAAARecord represents a single AAAA (Address) resource record in the Domain Name System (DNS).
// An AAAA record maps a domain name to an IPv6 address, enabling clients to locate servers
// and other resources on the IPv6 Internet.
//
// Fields:
//
//	IPv6: A string representing the IPv6 address associated with the domain name.
//	      The address is in colon-separated hexadecimal format (e.g., "2001:0db8:85a3:0000:0000:8a2e:0370:7334").
//
//	OriginalTTL: An unsigned 32-bit integer indicating the original time-to-live (TTL) value
//	             of the AAAA record. This value specifies the duration in seconds that the record
//	             may be cached before it should be discarded or refreshed.
type AAAARecord struct {
	IPv6        string
	OriginalTTL uint32
}

// String returns a formatted string representation of the AAAARecord.
// This method implements the fmt.Stringer interface for pretty-printing the record.
func (r *AAAARecord) String() string {
	return fmt.Sprintf(
		"ARecord:\n"+
			"  IPv4 Address: %s\n"+
			"  Original TTL: %d seconds\n",
		r.IPv6,
		r.OriginalTTL,
	)
}

// AAAAResponse represents the complete response for an AAAA record query.
// It includes a collection of AAAA records, the validation status of the response,
// any associated RRSIG record for DNSSEC validation, and the raw response received
// from the DNS server. This struct is particularly useful when dealing with
// responses that include multiple AAAA records for a single domain name.
//
// Fields:
//
//	Records: A slice of AAAARecord structs, each representing an individual AAAA record.
//	         Multiple AAAA records may be present if a domain name resolves to multiple
//	         IPv6 addresses.
//
//	Validated: A boolean flag indicating whether the AAAA records have been validated
//	           using DNSSEC validation procedures. True if validated, false otherwise.
//
//	RRSIG: A pointer to an RRSIGRecord struct that contains the DNSSEC signature for this
//	       AAAA record set. This field is nil if DNSSEC is not used or if the record is not signed.
//
//	RawResponse: A string containing the raw textual response received from the DNS server,
//	             which can be useful for logging, debugging, or other diagnostic purposes.
type AAAAResponse struct {
	Records     []AAAARecord
	Validated   bool
	RRSIG       *RRSIGRecord
	RawResponse string
}

// Parse parses a raw DNS response string and creates a new AAAAResponse struct.
// This function is specifically designed to work with the output of the 'delv' command-line tool
// for AAAA queries. The AAAA query is used to resolve a domain name to its IPv6 address.
// The parsed information from the 'delv' response is used to populate a AAAAResponse struct,
// which represents a structured interpretation of the AAAA records and associated data.
//
// Parameters:
//
//	response: A string containing the raw textual response from the 'delv' command-line tool.
//	          This response should be the result of an AAAA query for a specific domain.
//	          The response string is expected to include the AAAA records, along with
//	          any associated RRSIG records and other relevant DNS information.
//
// Return Value:
//
//	*AAAAResponse: A pointer to a AAAAResponse struct that contains the parsed AAAA records,
//	               the validation status, the associated RRSIG record (if available), and the raw response.
//	               This struct provides a structured representation of the IPv6 addresses
//	               and associated data extracted from the 'delv' response.
//
//	error: An error object that indicates any issues encountered during the parsing of the
//	       response string. If the parsing is successful, the error is nil. If parsing fails,
//	       the error provides details about the cause of the failure.
//
// Example Usage:
//
//	aaaaResponse, err := Parse(rawDelvResponse)
//	if err != nil {
//	    // Handle error
//	}
//	// Use aaaaResponse for DNS queries or other purposes
//
// Note:
//
//	This function is specifically designed to parse the output of the 'delv' command-line tool,
//	which is commonly used for DNS diagnostics and troubleshooting. The function assumes that the input
//	string is in the format provided by 'delv' and may not work correctly with responses from
//	other tools or in different formats.
func (r *AAAAResponse) Parse(response string) (DNSRecordResult, error) {
	lines := strings.Split(response, "\n")
	if strings.Contains(response, "resolution failed") {
		return nil, fmt.Errorf("resolution failed: %s", lines[0])
	}
	r.RawResponse = response
	aaaaRegex := regexp.MustCompile(`\bIN\s+AAAA\b`)
	rrsigRegex := regexp.MustCompile(`\bRRSIG\s+AAAA\b`)

	for _, line := range lines {
		if strings.HasPrefix(line, "; fully validated") {
			r.Validated = true
		} else if strings.HasPrefix(line, "; unsigned answer") {
			r.Validated = false
		} else if aaaaRegex.MatchString(line) {
			aaaaRecord := &AAAARecord{}
			parts := strings.Fields(line)
			if len(parts) < 5 {
				return nil, fmt.Errorf("invalid AAAA r: %s", line)
			}
			ttl, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid TTL '%s' in AAAA r: %v", parts[1], err)
			}
			aaaaRecord.OriginalTTL = uint32(int(ttl))

			aaaaRecord.IPv6 = parts[4]
			r.Records = append(r.Records, *aaaaRecord)
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

// Compare checks the equality between two instances of AAAARecord.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *AAAARecord) Compare(b *AAAARecord) bool {
	return r.IPv6 == b.IPv6
}

// Compare checks the equality between two instances of AAAAResponse.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *AAAAResponse) Compare(b *AAAAResponse) bool {
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
func (r *AAAAResponse) String() string {
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
