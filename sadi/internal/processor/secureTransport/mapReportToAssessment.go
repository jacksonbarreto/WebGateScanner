package secureTransport

func MapReportToAssessment(report Report) *Assessment {
	var assessment Assessment
	assessment.AssessmentId = report.Host
	assessment.Host = report.Host
	assessment.EngineVersion = report.EngineVersion
	assessment.CriteriaVersion = report.CriteriaVersion
	// TODO: Map full report to assessment
	return &assessment
}
