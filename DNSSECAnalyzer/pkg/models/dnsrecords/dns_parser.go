package dnsrecords

// DNSRecordParser is an interface that defines the standard method for parsing DNS record responses.
// Implementations of this interface are responsible for parsing raw DNS response strings
// and converting them into structured data types.
//
// The interface is designed to be flexible enough to handle different types of DNS records,
// such as DS, AAAA, DNSKEY, etc. Each specific record type will have its own implementation
// of the Parse method, tailored to extract the relevant information from that particular
// type of DNS response.
//
// Methods:
//
// Parse(response string) (DNSRecordResult, error)
//   - Parse takes a raw DNS response string as input and returns a DNSRecordResult.
//   - The response string is expected to be the output from a DNS query command (e.g., 'delv').
//   - The method returns a DNSRecordResult containing the parsed data, and an error if the parsing fails.
type DNSRecordParser interface {
	Parse(response string) (DNSRecordResult, error)
}

// DNSRecordResult is an interface that represents the result of parsing a DNS record response.
// This interface is implemented by structs that hold the parsed data of specific DNS record types.
//
// The DNSRecordResult interface is a generic container for the results of DNS record parsing.
// Each specific record type (e.g., DS, AAAA, DNSKEY) will have its own struct that implements
// this interface, allowing for type-specific data to be stored while still conforming to a
// general result type that can be used in more abstract contexts, such as storing in a collection
// of mixed result types.
//
// Implementations of DNSRecordResult should include fields that are relevant to the specific
// DNS record type they represent. For example, a struct representing the result of parsing
// a DS record might include fields for key tag, algorithm, digest type, digest, and validation status.
type DNSRecordResult interface{}
