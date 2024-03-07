package parser

import "github.com/jacksonbarreto/WebGateScanner/STLSDataParser/internal/models"

type IParser interface {
	ParseJson(response models.TestSSLResponse) (models.TestSSLResult, error)
}
