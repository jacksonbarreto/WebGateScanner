package models

import (
	"github.com/jacksonbarreto/WebGateScanner/DNSSECAnalyzer/pkg/models/dnsrecords"
	"time"
)

// Assessment represents the aggregation of results from a DNS scanner.
// It stores information about the scanning session, including the start and end times,
// the URL and domain being scanned, and a map of DNS record results.
//
// Fields:
//
//	Start: The time when the assessment started. Represented as a time.Time object.
//
//	End: The time when the assessment ended. Represented as a time.Time object.
//	     This field is initially zero and is set when the Finish() method is called.
//
//	Url: A string representing the URL associated with the assessment.
//
//	Domain: A string representing the domain being assessed.
//
//	Records: A map where the keys are string identifiers for DNS record types (e.g., "A", "AAAA", "MX"),
//	         and the values are dnsrecords.DNSRecordResult structs, which contain the results of
//	         querying each DNS record type.
//
// Constructor:
//
//	NewAssessment: Creates and initializes a new instance of Assessment with the specified URL and domain.
//	               The start time is set to the current time, and the map of records is initialized.
//
// Methods:
//
//	Finish: Marks the end of the assessment by setting the End field to the current time.
//
//	Begin: Resets the start time of the assessment to the current time. Useful for restarting the assessment.
//
// Usage Example:
//
//	// Create a new assessment for a specific domain
//	assessment := NewAssessment("https://example.com", "example.com")
//
//	// Perform scanning operations...
//
//	// Mark the assessment as finished
//	assessment.Finish()
type Assessment struct {
	Start   time.Time
	End     time.Time
	Url     string
	Domain  string
	Records map[string]dnsrecords.DNSRecordResult
}

// NewAssessment creates and initializes a new Assessment instance for a DNS scanning session.
// This function sets up the assessment with the specified URL and domain and initializes
// the start time to the current moment. It also prepares an empty map to store DNS record results.
//
// Parameters:
//
//	url: A string representing the URL associated with the assessment.
//	     This URL typically points to the target that is being scanned or assessed.
//
//	domain: A string representing the domain name being assessed.
//	        This domain is the focus of the DNS scanning operation.
//
// Returns:
//
//	*Assessment: A pointer to the newly created Assessment struct. This struct includes
//	             the start time of the assessment (set to the current time), the specified URL
//	             and domain, and an initialized empty map for DNS record results.
//
// Usage Example:
//
//	// Create a new assessment for a specific domain
//	assessment := NewAssessment("https://example.com", "example.com")
//
//	// The assessment can now be used to track DNS scanning results and other related information
//	// for the domain "example.com".
//
// Note:
//
//	The returned Assessment struct is ready for use in tracking DNS scanning results.
//	The Finish() method should be called on the Assessment struct once the scanning operation
//	is complete to mark the end time. The Begin() method can be used to reset the start time
//	if the assessment needs to be restarted.
func NewAssessment(url string, domain string) *Assessment {
	return &Assessment{
		Start:   time.Now(),
		Url:     url,
		Domain:  domain,
		Records: make(map[string]dnsrecords.DNSRecordResult),
	}
}

// Begin resets the start time of a DNS scanning session in the Assessment struct.
// This method updates the Start field with the current time, effectively restarting the
// timing of the assessment. It is useful for reinitializing the start time in scenarios
// where the DNS scanning process is restarted or delayed after initial creation of the
// Assessment instance.
//
// Usage:
//
//	This method should be used when there is a need to reset the start time of an ongoing
//	DNS scanning session. It ensures that the assessment accurately reflects the actual
//	start time of the scanning activities.
//
// Example Usage:
//
//	// Assume 'assessment' is an instance of Assessment that was created earlier
//	// and needs to be restarted for some reason
//	assessment.Begin()
//	// The 'Start' field of 'assessment' now contains the time at which the Begin method was called
//
// Note:
//
//   - The Begin method does not return any value. It only updates the 'Start' field of the
//     Assessment struct with the current time.
//   - Calling this method does not affect the other fields of the Assessment struct, such as
//     the 'End' field, URL, Domain, or the Records map. These fields retain their existing values.
//   - It is particularly useful in cases where there is a significant delay between the creation
//     of the Assessment instance and the actual start of DNS scanning activities.
func (a *Assessment) Begin() {
	a.Start = time.Now()
}

// Finish marks the end of a DNS scanning session by setting the End field of the Assessment struct.
// This method captures the current time as the end time of the assessment, indicating the completion
// of the DNS scanning operation. It is typically called after all DNS scanning activities have been
// completed and all relevant DNS record results have been stored in the Assessment struct.
//
// Usage:
//
//	This method should be called on an instance of the Assessment struct once the DNS scanning
//	process is finished. It finalizes the assessment by recording the end time.
//
// Example Usage:
//
//	// Assume 'assessment' is an instance of Assessment that has been used for DNS scanning
//	assessment.Finish()
//	// The 'End' field of 'assessment' now contains the time at which the Finish method was called
//
// Note:
//
//   - The Finish method does not return any value. It simply updates the 'End' field of the
//     Assessment struct with the current time.
//   - If the Finish method is called multiple times, the 'End' field will be updated to the time
//     of the most recent call.
//   - It is important to call this method to accurately reflect the duration of the DNS scanning
//     session, especially if timing or performance metrics are being considered.
func (a *Assessment) Finish() {
	a.End = time.Now()
}
