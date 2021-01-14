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
		assert.Equal(t, 7, len(auditReport.Vulnerabilities))

		assert.Equal(t, "low", auditReport.Vulnerabilities["@lhci/cli"].Severity)
		lvl, innerErr := ToLevel(auditReport.Vulnerabilities["@lhci/cli"].Severity)
		assert.Nil(t, innerErr)
		assert.Equal(t, LevelLow, lvl)
		assert.True(t, auditReport.Vulnerabilities["@lhci/cli"].FixAvailable.FixAvailable)

		assert.Equal(t, "low", auditReport.Vulnerabilities["@lhci/utils"].Severity)
		lvl, innerErr = ToLevel(auditReport.Vulnerabilities["@lhci/utils"].Severity)
		assert.Nil(t, innerErr)
		assert.Equal(t, LevelLow, lvl)
		assert.True(t, auditReport.Vulnerabilities["@lhci/utils"].FixAvailable.FixAvailable)

		assert.Equal(t, "low", auditReport.Vulnerabilities["@xivart/tangram"].Severity)
		lvl, innerErr = ToLevel(auditReport.Vulnerabilities["@xivart/tangram"].Severity)
		assert.Nil(t, innerErr)
		assert.Equal(t, LevelLow, lvl)
		assert.False(t, auditReport.Vulnerabilities["@xivart/tangram"].FixAvailable.FixAvailable)

		assert.Equal(t, "low", auditReport.Vulnerabilities["isomorphic-fetch"].Severity)
		lvl, innerErr = ToLevel(auditReport.Vulnerabilities["isomorphic-fetch"].Severity)
		assert.Nil(t, innerErr)
		assert.Equal(t, LevelLow, lvl)
		assert.False(t, auditReport.Vulnerabilities["isomorphic-fetch"].FixAvailable.FixAvailable)

		assert.Equal(t, 7, auditReport.Metadata.Vulnerabilities.Total)
		assert.Equal(t, 535, auditReport.Metadata.Dependencies.Prod)
		assert.Equal(t, 3237, auditReport.Metadata.Dependencies.Dev)
	})
}
