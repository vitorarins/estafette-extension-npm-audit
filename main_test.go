package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuditRepository(t *testing.T) {

	finding146 := Finding{"1.9.2", true, false, false}
	finding534 := Finding{"2.2.0", true, false, false}
	advisories := map[int]Advisory{
		146: Advisory{146, "critical", []Finding{finding146}},
		534: Advisory{534, "low", []Finding{finding534}},
	}
	vulnerabilities := Vulnerabilities{0, 1, 0, 0, 1}
	metadata := Metadata{vulnerabilities, 527, 39, 0, 566}
	var auditReport AuditReportBody
	auditReport = AuditReportBody{
		advisories,
		metadata,
	}

	t.Run("AuditRepositoryLowProdCriticalDev", func(t *testing.T) {

		prodVulnLevel := Level(Low)
		devVulnLevel := Level(Critical)
		failBuild := checkIfBuildShouldFail(auditReport, prodVulnLevel, devVulnLevel)
		assert.True(t, failBuild)
	})

	t.Run("AuditRepositoryLowProdLowDev", func(t *testing.T) {

		prodVulnLevel := Level(Low)
		devVulnLevel := Level(Low)
		failBuild := checkIfBuildShouldFail(auditReport, prodVulnLevel, devVulnLevel)
		assert.True(t, failBuild)
	})

	t.Run("AuditRepositoryLowProdNoneDev", func(t *testing.T) {

		prodVulnLevel := Level(Low)
		devVulnLevel := Level(None)
		failBuild := checkIfBuildShouldFail(auditReport, prodVulnLevel, devVulnLevel)
		assert.False(t, failBuild)
	})
}
