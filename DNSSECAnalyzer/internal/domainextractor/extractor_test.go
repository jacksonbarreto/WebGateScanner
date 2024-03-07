package domainextractor

import (
	"testing"
)

func TestExtractDomain(t *testing.T) {
	testCases := []struct {
		url         string
		expected    string
		expectError bool
	}{
		{"http://www.example.com", "example.com", false},
		{"https://example.com", "example.com", false},
		{"example.com", "example.com", false},
		{"https://subdomain.example.com", "subdomain.example.com", false},
		{"https://www.subdomain.example.com", "subdomain.example.com", false},
		{"ftp://example.com/resource", "example.com", false},
		{"http://www.example.com:8080", "example.com", false},
		{"https://www.example.com/path?query=string", "example.com", false},
		{"http://invalid-url", "", true},
		{"invalid-url", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.url, func(t *testing.T) {
			domain, err := ExtractDomain(tc.url)
			if (err != nil) != tc.expectError {
				t.Errorf("ExtractDomain(%s): unexpected error status: %v", tc.url, err)
			}
			if domain != tc.expected {
				t.Errorf("ExtractDomain(%s): expected %s, got %s", tc.url, tc.expected, domain)
			}
		})
	}
}
