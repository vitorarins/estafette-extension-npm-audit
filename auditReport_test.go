package main

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalAuditReport(t *testing.T) {

	t.Run("Unmarshal", func(t *testing.T) {

		data, err := ioutil.ReadFile("test-report.json")
		assert.Nil(t, err)

		var auditReport AuditReport

		// act
		err = json.Unmarshal(data, &auditReport)

		assert.NotNil(t, auditReport)

		assert.Equal(t, 2, auditReport.AuditReportVersion)
		assert.Equal(t, 1, len(auditReport.Vulnerabilities))
		assert.Equal(t, "low", auditReport.Vulnerabilities["ini"].Severity)
		lvl, innerErr := ToLevel(auditReport.Vulnerabilities["ini"].Severity)
		assert.Nil(t, innerErr)
		assert.Equal(t, LevelLow, lvl)
		assert.True(t, auditReport.Vulnerabilities["ini"].FixAvailable)

		assert.Equal(t, 1, auditReport.Metadata.Vulnerabilities.Total)
		assert.Equal(t, 53, auditReport.Metadata.Dependencies.Prod)
		assert.Equal(t, 1288, auditReport.Metadata.Dependencies.Dev)
		assert.Equal(t, 1341, auditReport.Metadata.Dependencies.Total)

	})
}
