package parser

import "github.com/jacksonbarreto/WebGateScanner/internal/models"

type IParser interface {
	ParseJson(response models.TestSSLResponse) (models.TestSSLResult, error)
}
