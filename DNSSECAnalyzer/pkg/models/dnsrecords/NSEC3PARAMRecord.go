package dnsrecords

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// NSEC3PARAMRecord represents a single NSEC3PARAM (NSEC3 Parameters) resource record in DNSSEC.
// NSEC3PARAM records are used to specify the parameters of the NSEC3 protocol, which provides
// authenticated denial of existence in a way that prevents zone enumeration.
//
// Fields:
//
//	TTL: An unsigned 32-bit integer indicating the time-to-live (TTL) value of the NSEC3PARAM record.
//	     Specifies the duration in seconds that the record may be cached before it should be
//	     discarded or refreshed.
//
//	HashAlgorithm: An unsigned 8-bit integer specifying the cryptographic hash algorithm used
//	               to generate NSEC3 hashes. Common values are defined in DNSSEC standards.
//
//	Flags: An unsigned 8-bit integer containing various flags relating to the NSEC3PARAM record.
//	       These flags control certain aspects of NSEC3 processing.
//
//	Iterations: An unsigned 16-bit integer representing the number of additional times the hash
//	            is performed. A higher number increases the difficulty of reversing the hash.
//
//	SaltLength: An unsigned 8-bit integer indicating the length of the salt value used in the hash.
//
//	Validated: A boolean flag indicating whether the NSEC3PARAM record has been validated
//	           using DNSSEC validation procedures. True if validated, false otherwise.
//
//	RRSIG: A pointer to an RRSIGRecord struct containing the DNSSEC signature for the NSEC3PARAM record.
//	       This field may be nil if DNSSEC is not used or if the record is not signed.
//	RawResponse: The raw text of the DNS response containing the NSEC3PARAM (NSEC3 Parameters) record.
type NSEC3PARAMRecord struct {
	TTL           uint32
	HashAlgorithm uint8
	Flags         uint8
	Iterations    uint16
	SaltLength    uint8
	Validated     bool
	RRSIG         *RRSIGRecord
	RawResponse   string
}

// Parse parses a raw DNS response string and creates a new NSEC3PARAMRecord struct.
// This function is specifically designed to work with the output of the 'delv' command-line tool
// for NSEC3PARAM queries in the context of DNSSEC. NSEC3PARAM records specify parameters for
// the NSEC3 protocol, which enhances DNSSEC by preventing zone walking. The parsed information
// from the 'delv' response is used to populate a NSEC3PARAMRecord struct.
//
// Parameters:
//
//	response: A string containing the raw textual response from the 'delv' command-line tool.
//	          This response should be the result of an NSEC3PARAM query for a specific domain.
//	          The response string is expected to include the NSEC3PARAM record, along with
//	          any associated RRSIG records and other relevant DNSSEC information.
//
// Return Value:
//
//	*NSEC3PARAMRecord: A pointer to a NSEC3PARAMRecord struct that contains the parsed NSEC3PARAM
//	                   record details, including hash algorithm, flags, iterations, and salt length.
//	                   The struct also includes the validation status and any associated RRSIG record.
//
//	error: An error object that indicates any issues encountered during the parsing of the
//	       response string. If the parsing is successful, the error is nil. If parsing fails,
//	       the error provides details about the cause of the failure.
//
// Example Usage:
//
//	nsec3paramRecord, err := Parse(rawDelvResponse)
//	if err != nil {
//	    // Handle error
//	}
//	// Use nsec3paramRecord for DNSSEC-related tasks or analysis
//
// Note:
//
//	This function is specifically designed to parse the output of the 'delv' command-line tool,
//	which is commonly used for DNSSEC diagnostics and troubleshooting. The function assumes that the input
//	string is in the format provided by 'delv' and may not work correctly with responses from
//	other tools or in different formats.
func (r *NSEC3PARAMRecord) Parse(response string) (DNSRecordResult, error) {
	lines := strings.Split(response, "\n")
	if strings.Contains(response, "resolution failed") {
		return nil, fmt.Errorf("resolution failed: %s", lines[0])
	}
	r.RawResponse = response
	nsec3ParamRegex := regexp.MustCompile(`\bIN\s+NSEC3PARAM\b`)
	rrsigNsecParamRegex := regexp.MustCompile(`\bRRSIG\s+NSEC3PARAM\b`)

	for _, line := range lines {
		if strings.HasPrefix(line, "; fully validated") {
			r.Validated = true
		} else if strings.HasPrefix(line, "; unsigned answer") {
			r.Validated = false
		} else if nsec3ParamRegex.MatchString(line) {
			parts := strings.Fields(line)
			if len(parts) < 8 {
				return nil, fmt.Errorf("invalid NSEC3PARAMRecord r: %s", line)
			}
			ttl, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid TTL '%s' in NSEC3PARAMRecord r: %v", parts[1], err)
			}
			r.TTL = uint32(int(ttl))

			hashAlgorithm, err := strconv.ParseUint(parts[4], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid Hash Algorithm '%s' in NSEC3PARAMRecord r: %v", parts[4], err)
			}
			r.HashAlgorithm = uint8(int(hashAlgorithm))

			flags, err := strconv.ParseUint(parts[5], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid Flags '%s' in NSEC3PARAMRecord r: %v", parts[5], err)
			}
			r.Flags = uint8(int(flags))

			iterations, err := strconv.ParseUint(parts[6], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid Iterations '%s' in NSEC3PARAMRecord r: %v", parts[6], err)
			}
			r.Iterations = uint16(int(iterations))

			saltLength, err := strconv.ParseUint(parts[7], 10, 8)
			if err != nil {
				if parts[7] == "-" {
					saltLength = 0
				} else {
					return nil, fmt.Errorf("invalid Salt Length '%s' in NSEC3PARAMRecord r: %v", parts[7], err)
				}
			}
			r.SaltLength = uint8(int(saltLength))

		} else if rrsigNsecParamRegex.MatchString(line) {
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

// Compare checks the equality between two instances of NSEC3PARAMRecord.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *NSEC3PARAMRecord) Compare(b *NSEC3PARAMRecord) bool {
	return r.TTL == b.TTL &&
		r.HashAlgorithm == b.HashAlgorithm &&
		r.Flags == b.Flags &&
		r.Iterations == b.Iterations &&
		r.SaltLength == b.SaltLength &&
		r.Validated == b.Validated &&
		r.RRSIG.Compare(b.RRSIG) &&
		r.RawResponse == b.RawResponse
}

// String returns a formatted string representation of the NSEC3PARAMRecord.
// This method provides a readable view of the NSEC3PARAM record's details, including TTL, hash algorithm, and more.
func (r *NSEC3PARAMRecord) String() string {
	if r == nil {
		return "<null>"
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
		"NSEC3PARAMRecord:\n"+
			"  TTL: %d\n"+
			"  Hash Algorithm: %d\n"+
			"  Flags: %d\n"+
			"  Iterations: %d\n"+
			"  Salt Length: %d\n"+
			"  Validated: %s\n"+
			"  RRSIG: %s\n"+
			"  Raw Response: %s\n",
		r.TTL,
		r.HashAlgorithm,
		r.Flags,
		r.Iterations,
		r.SaltLength,
		validatedStr,
		rrsigStr,
		r.RawResponse,
	)
}
