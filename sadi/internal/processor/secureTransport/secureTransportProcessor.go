package secureTransport

import (
	"encoding/json"
)

type Processor struct {
	repository Repository
}

type Repository interface {
	Save(data Assessment) error
}

func NewSecureTransportProcessor(repo Repository) *Processor {
	return &Processor{
		repository: repo,
	}
}

func (stp *Processor) Process(payload string) error {
	var data Report
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		// TODO: Handle errors
		return err
	}

	assessment := MapReportToAssessment(data)

	err = stp.repository.Save(*assessment)
	if err != nil {
		// TODO: Handle errors
		return err
	}

	return nil
}
