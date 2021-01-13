package main

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadAuditReport(t *testing.T) {

	t.Run("ReadAuditReport", func(t *testing.T) {

		testString := string(`{
  "actions": [
    {
      "action": "review",
      "module": "https-proxy-agent",
      "resolves": [
        {
          "id": 146,
          "dev": false,
          "optional": false,
          "bundled": false
        },
        {
          "id": 534,
          "dev": true,
          "optional": false,
          "bundled": false
        },
        {
          "id": 550,
          "dev": false,
          "optional": false,
          "bundled": false
        }
      ]
    }
  ],
  "advisories": {
    "146": {
      "findings": [
        {
          "version": "1.9.2",
          "optional": false,
          "bundled": false
        }
      ],
      "id": 146,
      "severity": "moderate"
    },
    "534": {
      "findings": [
        {
          "version": "2.2.0",
          "optional": false,
          "bundled": false
        }
      ],
      "id": 534,
      "severity": "critical"
    },
    "550": {
      "findings": [
        {
          "version": "2.0.3",
          "optional": false,
          "bundled": false
        }
      ],
      "id": 550,
      "severity": "critical"
    }
  },
  "metadata": {
    "vulnerabilities": {
      "info": 0,
      "low": 3,
      "moderate": 1,
      "high": 1,
      "critical": 2
    },
    "dependencies": 391,
    "devDependencies": 39,
    "optionalDependencies": 0,
    "totalDependencies": 430
  }
}
`)
		var auditReport AuditReportBody
		auditReport = readAuditReport(testString)

		assert.NotNil(t, auditReport)

		assert.Equal(t, 146, auditReport.Advisories[146].Id)
		assert.Equal(t, "moderate", auditReport.Advisories[146].Severity)
		assert.Equal(t, "1.9.2", auditReport.Advisories[146].Findings[0].Version)
		assert.Equal(t, false, auditReport.Advisories[146].Findings[0].Optional)
		assert.Equal(t, false, auditReport.Advisories[146].Findings[0].Bundled)

		assert.Equal(t, 534, auditReport.Advisories[534].Id)
		assert.Equal(t, "critical", auditReport.Advisories[534].Severity)
		assert.Equal(t, "2.2.0", auditReport.Advisories[534].Findings[0].Version)
		assert.Equal(t, false, auditReport.Advisories[534].Findings[0].Optional)
		assert.Equal(t, false, auditReport.Advisories[534].Findings[0].Bundled)

		assert.Equal(t, 550, auditReport.Advisories[550].Id)
		assert.Equal(t, "critical", auditReport.Advisories[550].Severity)
		assert.Equal(t, "2.0.3", auditReport.Advisories[550].Findings[0].Version)
		assert.Equal(t, false, auditReport.Advisories[550].Findings[0].Optional)
		assert.Equal(t, false, auditReport.Advisories[550].Findings[0].Bundled)

		assert.Equal(t, 0, auditReport.Metadata.Vulnerabilities.Info)
		assert.Equal(t, 3, auditReport.Metadata.Vulnerabilities.Low)
		assert.Equal(t, 1, auditReport.Metadata.Vulnerabilities.Moderate)
		assert.Equal(t, 1, auditReport.Metadata.Vulnerabilities.High)
		assert.Equal(t, 2, auditReport.Metadata.Vulnerabilities.Critical)

		assert.Equal(t, 391, auditReport.Metadata.Dependencies)
		assert.Equal(t, 39, auditReport.Metadata.DevDependencies)
		assert.Equal(t, 0, auditReport.Metadata.OptionalDependencies)
		assert.Equal(t, 430, auditReport.Metadata.TotalDependencies)
	})
}

func TestUnmarshal(t *testing.T) {

	t.Run("ReadAuditReport", func(t *testing.T) {

		data, err := ioutil.ReadFile("test-report.json")
		assert.Nil(t, err)
		var auditReportBody AuditReportBody

		// act
		err = json.Unmarshal(data, &auditReportBody)

		assert.Nil(t, err)
	})
}
