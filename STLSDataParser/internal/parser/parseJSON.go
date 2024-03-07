package parser

import "github.com/jacksonbarreto/WebGateScanner/internal/models"

type Parser struct {
	// I will need include logger
}

func New() *Parser {
	return &Parser{}
}

func (p *Parser) ParseJson(response models.TestSSLResponse) (models.TestSSLResult, error) {
	var result = models.TestSSLResult{}

	result.Endpoints = make([]models.Endpoint, len(response.ScanResult))
	for i, endpoint := range response.ScanResult {
		result.Endpoints[i] = models.Endpoint{
			IpAddress: endpoint.IP,
		}
	}

	return result, nil
}
