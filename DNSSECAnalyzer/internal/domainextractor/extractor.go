package domainextractor

import (
	"errors"
	"net/url"
	"strings"
)

func ExtractDomain(urlStr string) (string, error) {
	if !strings.Contains(urlStr, "://") {
		urlStr = "https://" + urlStr
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	hostname := parsedURL.Hostname()

	if !strings.Contains(hostname, ".") {
		return "", errors.New("invalid hostname or domain missing")
	}

	if strings.HasPrefix(hostname, "www.") {
		hostname = strings.TrimPrefix(hostname, "www.")
	}

	return hostname, nil
}
