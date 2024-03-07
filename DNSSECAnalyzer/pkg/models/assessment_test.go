package models

import (
	"bou.ke/monkey"
	"testing"
	"time"
)

func TestNewAssessment(t *testing.T) {
	url := "https://example.com"
	domain := "example.com"
	assessment := NewAssessment(url, domain)

	if assessment.Url != url {
		t.Errorf("expected URL to be %s, got %s", url, assessment.Url)
	}

	if assessment.Domain != domain {
		t.Errorf("expected domain to be %s, got %s", domain, assessment.Domain)
	}

	if assessment.Records == nil {
		t.Errorf("expected Records to be initialized, got nil")
	}

	if assessment.Start.IsZero() {
		t.Errorf("expected Start to be initialized, got zero time")
	}
}

func TestAssessmentBegin(t *testing.T) {
	fakeTime := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	monkey.Patch(time.Now, func() time.Time {
		return fakeTime
	})

	assessment := NewAssessment("https://example.com", "example.com")

	assessment.Begin()

	if assessment.Start != fakeTime {
		t.Errorf("Expected start time to be %v, got %v", fakeTime, assessment.Start)
	}

	monkey.Unpatch(time.Now)
}

func TestAssessmentFinish(t *testing.T) {
	fakeTime := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	monkey.Patch(time.Now, func() time.Time {
		return fakeTime
	})

	assessment := NewAssessment("https://example.com", "example.com")

	fakeTime = fakeTime.Add(3 * time.Second)

	assessment.Finish()

	if assessment.End != fakeTime {
		t.Errorf("Expected end time to be %v, got %v", fakeTime, assessment.End)
	}

	monkey.Unpatch(time.Now)
}
