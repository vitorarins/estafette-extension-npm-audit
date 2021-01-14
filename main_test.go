package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuditRepository(t *testing.T) {
	t.Run("FailBuildIfProdReportHasFixableVulnerabilitiesOfProdLevel", func(t *testing.T) {

		prodVulnLevel := LevelLow
		prodReport := &AuditReport{
			Vulnerabilities: map[string]Vulnerability{
				"ini": {
					Severity:     "moderate",
					FixAvailable: true,
				},
			},
		}

		devVulnLevel := LevelNone
		devReport := &AuditReport{}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.True(t, failBuild)
		assert.True(t, hasVulns)
	})

	t.Run("FailBuildIfProdReportHasFixableVulnerabilitiesHigherThanProdLevel", func(t *testing.T) {

		prodVulnLevel := LevelHigh
		prodReport := &AuditReport{
			Vulnerabilities: map[string]Vulnerability{
				"ini": {
					Severity:     "critical",
					FixAvailable: true,
				},
			},
		}

		devVulnLevel := LevelNone
		devReport := &AuditReport{}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.True(t, failBuild)
		assert.True(t, hasVulns)
	})

	t.Run("DoNotFailBuildIfProdReportHasNoFixableVulnerabilitiesEvenIfItsOfProdLevel", func(t *testing.T) {

		prodVulnLevel := LevelLow
		prodReport := &AuditReport{
			Vulnerabilities: map[string]Vulnerability{
				"ini": {
					Severity:     "moderate",
					FixAvailable: false,
				},
			},
		}

		devVulnLevel := LevelNone
		devReport := &AuditReport{}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.False(t, failBuild)
		assert.False(t, hasVulns)
	})

	t.Run("DoNotFailBuildIfProdReportHasVulnerabilitiesLowerThanProdLevel", func(t *testing.T) {

		prodVulnLevel := LevelHigh
		prodReport := &AuditReport{
			Vulnerabilities: map[string]Vulnerability{
				"ini": {
					Severity:     "moderate",
					FixAvailable: true,
				},
			},
		}

		devVulnLevel := LevelNone
		devReport := &AuditReport{}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.False(t, failBuild)
		assert.True(t, hasVulns)
	})

	t.Run("FailBuildIfDevReportHasFixableVulnerabilitiesOfDevLevel", func(t *testing.T) {

		prodVulnLevel := LevelNone
		prodReport := &AuditReport{}

		devVulnLevel := LevelLow
		devReport := &AuditReport{
			Vulnerabilities: map[string]Vulnerability{
				"ini": {
					Severity:     "moderate",
					FixAvailable: true,
				},
			},
		}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.True(t, failBuild)
		assert.True(t, hasVulns)
	})

	t.Run("FailBuildIfDevReportHasFixableVulnerabilitiesHigherThanDevLevel", func(t *testing.T) {

		prodVulnLevel := LevelNone
		prodReport := &AuditReport{}

		devVulnLevel := LevelHigh
		devReport := &AuditReport{Vulnerabilities: map[string]Vulnerability{
			"ini": {
				Severity:     "critical",
				FixAvailable: true,
			},
		},
		}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.True(t, failBuild)
		assert.True(t, hasVulns)
	})

	t.Run("DoNotFailBuildIfDevReportHasNoFixableVulnerabilitiesEvenIfItsOfDevLevel", func(t *testing.T) {

		prodVulnLevel := LevelNone
		prodReport := &AuditReport{}

		devVulnLevel := LevelLow
		devReport := &AuditReport{
			Vulnerabilities: map[string]Vulnerability{
				"ini": {
					Severity:     "moderate",
					FixAvailable: false,
				},
			},
		}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.False(t, failBuild)
		assert.False(t, hasVulns)
	})

	t.Run("DoNotFailBuildIfDevReportHasVulnerabilitiesLowerThanDevLevel", func(t *testing.T) {

		prodVulnLevel := LevelNone
		prodReport := &AuditReport{}

		devVulnLevel := LevelHigh
		devReport := &AuditReport{
			Vulnerabilities: map[string]Vulnerability{
				"ini": {
					Severity:     "moderate",
					FixAvailable: true,
				},
			},
		}

		// act
		failBuild, hasVulns, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)

		assert.Nil(t, err)
		assert.False(t, failBuild)
		assert.True(t, hasVulns)
	})
}

func TestGetSlackClient(t *testing.T) {
	slackChannels := "builds,builds-estafette"
	slackWorkspace := "estafette"
	slackCredentialsJSON := `[{
"name": "estafette",
"type": "idk",
"additionalProperties": {
  "workspace": "estafette",
  "webhook": "https://estafette.slack.com/webhook"
  }
}]`

	t.Run("GetSlackIntegration", func(t *testing.T) {
		// act
		slackEnabled, slackWebhookClient := getSlackIntegration(slackChannels, slackCredentialsJSON, slackWorkspace)

		assert.True(t, slackEnabled)
		assert.NotNil(t, slackWebhookClient)
	})

	t.Run("GetSlackIntegrationNoChannels", func(t *testing.T) {
		noChannels := ""

		// act
		slackEnabled, slackWebhookClient := getSlackIntegration(noChannels, slackCredentialsJSON, slackWorkspace)

		assert.False(t, slackEnabled)
		assert.Nil(t, slackWebhookClient)
	})

	t.Run("GetSlackIntegrationNoWebhookURLWithCredentials", func(t *testing.T) {

		// act
		slackEnabled, slackWebhookClient := getSlackIntegration(slackChannels, slackCredentialsJSON, slackWorkspace)

		assert.True(t, slackEnabled)
		assert.NotNil(t, slackWebhookClient)
	})
}
