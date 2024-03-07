package dnsrecords

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DNSKEYRecord represents a single DNSKEY resource record in DNSSEC.
// DNSKEY records are used to store public keys associated with a DNS zone,
// and they play a critical role in DNSSEC's ability to authenticate DNS records.
//
// Fields:
//
//	Flags: An unsigned 16-bit integer specifying operational parameters of the DNSKEY.
//	       Common values include 256 (Zone Signing Key) and 257 (Key Signing Key).
//
//	Protocol: An unsigned 8-bit integer that should always be 3, as per RFC 4034.
//
//	Algorithm: An unsigned 8-bit integer identifying the cryptographic algorithm used
//	           for the key. The value corresponds to specific DNSSEC algorithm types
//	           such as RSASHA1 or ECDSAP256SHA256.
//
//	PublicKey: A base64-encoded string representing the public key associated with the DNS zone.
//
//	KeyType: A human-readable string indicating the type of key (e.g., "ZSK" for Zone Signing Key,
//	         "KSK" for Key Signing Key).
//
//	AlgorithmName: A human-readable string representing the name of the cryptographic algorithm,
//	               such as "RSASHA256" or "ED25519".
//
//	KeyID: An unsigned 16-bit integer representing the DNSKEY record's identification value,
//	       often used to reference this key in related DNSSEC records like DS or RRSIG.
type DNSKEYRecord struct {
	Flags         uint16
	Protocol      uint8
	Algorithm     uint8
	PublicKey     string
	KeyType       string
	AlgorithmName string
	KeyID         uint16
}

// String returns a formatted string representation of the DNSKEYRecord.
// It includes details like flags, protocol, algorithm, and the public key.
func (r *DNSKEYRecord) String() string {
	if r == nil {
		return "<null>"
	}

	return fmt.Sprintf(
		"DNSKEYRecord:\n"+
			"  Flags: %d\n"+
			"  Protocol: %d\n"+
			"  Algorithm: %d\n"+
			"  Public Key: %s\n"+
			"  Key Type: %s\n"+
			"  Algorithm Name: %s\n"+
			"  Key ID: %d\n",
		r.Flags,
		r.Protocol,
		r.Algorithm,
		r.PublicKey,
		r.KeyType,
		r.AlgorithmName,
		r.KeyID,
	)
}

// DNSKEYResponse represents the complete response for a DNSKEY query.
// It includes a collection of DNSKEY records, the validation status of the response,
// any associated RRSIG record, and the raw response received from the DNS server.
//
// Fields:
//
//	Records: A slice of DNSKEYRecord structs, each representing an individual DNSKEY record.
//	         Multiple DNSKEY records are typically present in a DNSKEY query response, as they
//	         represent different keys used for signing various aspects of a DNS zone.
//
//	Validated: A boolean flag indicating whether the DNSKEY records have been validated
//	           using DNSSEC validation procedures. True if validated, false otherwise.
//
//	RRSIG: A pointer to an RRSIGRecord struct that contains the DNSSEC signature for this
//	       DNSKEY record set. This field is nil if DNSSEC is not used or if the record is not signed.
//
//	RawResponse: A string containing the raw textual response received from the DNS server,
//	             useful for logging, debugging, or other diagnostic purposes.
type DNSKEYResponse struct {
	Records     []DNSKEYRecord
	Validated   bool
	RRSIG       *RRSIGRecord
	RawResponse string
}

// Parse parses a raw DNS response string and creates a new DNSKEYResponse struct.
// This function is designed to work with the output of the 'delv' command-line tool specifically
// for DNSKEY queries within the context of DNSSEC. The parsed information is used to populate
// a DNSKEYResponse struct, which represents a structured interpretation of the DNSKEY records
// and associated data.
//
// Parameters:
//
//	response: A string containing the raw textual response from the 'delv' command-line tool.
//	          This response should be the result of a DNSKEY query for a specific domain.
//	          The response string is expected to include the DNSKEY records, along with
//	          any associated RRSIG records and other relevant DNSSEC information.
//
// Return Value:
//
//	*DNSKEYResponse: A pointer to a DNSKEYResponse struct that contains the parsed DNSKEY records,
//	                 the validation status, the associated RRSIG record (if available), and the raw response.
//	                 This struct provides a structured representation of the DNSSEC public keys
//	                 and associated data extracted from the 'delv' response.
//
//	error: An error object that indicates any issues encountered during the parsing of the
//	       response string. If the parsing is successful, the error is nil. If parsing fails,
//	       the error provides details about the cause of the failure.
//
// Example Usage:
//
//	dnskeyResponse, err := Parse(rawDelvResponse)
//	if err != nil {
//	    // Handle error
//	}
//	// Use dnskeyResponse for DNSSEC validation or other purposes
//
// Note:
//
//	This function is specifically designed to parse the output of the 'delv' command-line tool,
//	which is used for DNSSEC diagnostics and troubleshooting. The function assumes that the input
//	string is in the format provided by 'delv' and may not work correctly with responses from
//	other tools or in different formats.
func (r *DNSKEYResponse) Parse(response string) (DNSRecordResult, error) {
	lines := strings.Split(response, "\n")
	if strings.Contains(response, "resolution failed") {
		return nil, fmt.Errorf("resolution failed: %s", lines[0])
	}
	r.RawResponse = response
	dnsKeyRegex := regexp.MustCompile(`\bIN\s+DNSKEY\b`)
	rrsigRegex := regexp.MustCompile(`\bRRSIG\s+DNSKEY\b`)

	for _, line := range lines {
		if strings.HasPrefix(line, "; fully validated") {
			r.Validated = true
		} else if strings.HasPrefix(line, "; unsigned answer") {
			r.Validated = false
		} else if dnsKeyRegex.MatchString(line) {
			dnskeyRecord := &DNSKEYRecord{}
			parts := strings.Fields(line)
			if len(parts) < 8 {
				return nil, fmt.Errorf("invalid DNSKEY r: %s", line)
			}

			flags, err := strconv.ParseUint(parts[4], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid flags '%s' in DNSKEY r: %v", parts[4], err)
			}
			dnskeyRecord.Flags = uint16(int(flags))

			protocol, err := strconv.ParseUint(parts[5], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid protocol '%s' in DNSKEY r: %v", parts[5], err)
			}
			dnskeyRecord.Protocol = uint8(int(protocol))

			algorithm, err := strconv.ParseUint(parts[6], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid algorithm '%s' in DNSKEY r: %v", parts[6], err)
			}
			dnskeyRecord.Algorithm = uint8(algorithm)

			comments := strings.Split(strings.Join(parts[7:], " "), ";")
			if len(comments) > 1 {
				for _, comment := range comments[1:] {
					if strings.Contains(comment, "alg =") {
						dnskeyRecord.AlgorithmName = strings.TrimSpace(strings.Split(comment, "=")[1])
					} else if strings.Contains(comment, "key id =") {
						keyID, err := strconv.ParseUint(strings.TrimSpace(strings.Split(comment, "=")[1]), 10, 16)
						if err != nil {
							return nil, fmt.Errorf("invalid key id '%s' in DNSKEY r: %v", strings.TrimSpace(strings.Split(comment, "=")[1]), err)
						}
						dnskeyRecord.KeyID = uint16(int(keyID))
					} else if strings.Contains(comment, "ZSK") || strings.Contains(comment, "KSK") {
						keyTypeParts := strings.Fields(comment)
						if len(keyTypeParts) > 0 {
							dnskeyRecord.KeyType = keyTypeParts[0]
						} else {
							return nil, fmt.Errorf("invalid key type '%s' in DNSKEY r: %v", comment, err)
						}
					}
				}
			} else {
				return nil, fmt.Errorf("invalid DNSKEY r: %s", line)
			}

			semicolonIndex := strings.Index(line, ";")
			if semicolonIndex == -1 {
				return nil, fmt.Errorf("missing ';' in DNSKEY r: %s", line)
			}

			publicKeyParts := parts[7:]
			for i, part := range parts {
				if i >= 7 && strings.Contains(part, ";") {
					publicKeyParts = parts[7:i]
					break
				}
			}
			dnskeyRecord.PublicKey = strings.Join(publicKeyParts, "")

			r.Records = append(r.Records, *dnskeyRecord)
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

// Compare checks the equality between two instances of DNSKEYRecord.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *DNSKEYRecord) Compare(b *DNSKEYRecord) bool {
	return r.Flags == b.Flags &&
		r.Protocol == b.Protocol &&
		r.Algorithm == b.Algorithm &&
		r.PublicKey == b.PublicKey &&
		r.KeyType == b.KeyType &&
		r.AlgorithmName == b.AlgorithmName &&
		r.KeyID == b.KeyID
}

// Compare checks the equality between two instances of DNSKEYResponse.
// This function is useful for testing and validation purposes.
//
// Parameters:
// - b: A reference to another instance for comparison.
//
// Returns:
//   - bool: Returns true if the corresponding properties of 'a' and 'b' are equal,
//     otherwise, returns false.
func (r *DNSKEYResponse) Compare(b *DNSKEYResponse) bool {
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

// String returns a formatted string representation of the DNSKEYResponse.
// It provides a human-readable view of the response, including the records, validation status, and raw response.
func (r *DNSKEYResponse) String() string {
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
		"DNSKEYResponse:\n"+
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
