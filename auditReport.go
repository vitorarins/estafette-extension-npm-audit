package main

import "encoding/json"

// AuditReport represents the body coming from npm audit
type AuditReport struct {
	AuditReportVersion int                      `json:"auditReportVersion,omitempty"`
	Vulnerabilities    map[string]Vulnerability `json:"vulnerabilities,omitempty"`
	Metadata           Metadata                 `json:"metadata,omitempty"`
	Error              CommandError             `json:"error,omitempty"`
}

type Vulnerability struct {
	Severity     string                    `json:"severity,omitempty"`
	FixAvailable VulnerabilityFixAvailable `json:"fixAvailable,omitempty"`
}

type Metadata struct {
	Vulnerabilities MetadataVulnerabilities `json:"vulnerabilities,omitempty"`
	Dependencies    MetadataDependencies    `json:"dependencies,omitempty"`
}

type MetadataVulnerabilities struct {
	Total int `json:"total,omitempty"`
}

type MetadataDependencies struct {
	Prod int `json:"prod,omitempty"`
	Dev  int `json:"dev,omitempty"`
}

type CommandError struct {
	Code    string `json:"code,omitempty"`
	Summary string `json:"summary,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// StringOrStringArray is used to unmarshal/marshal either a single string value or a string array
type VulnerabilityFixAvailable struct {
	FixAvailable bool
}

func (b *VulnerabilityFixAvailable) UnmarshalJSON(data []byte) error {

	var asBool bool
	err := json.Unmarshal(data, &asBool)
	if err == nil {
		b.FixAvailable = asBool

		return nil
	}

	var aux struct {
		Name string `json:"name,omitempty"`
	}
	err = json.Unmarshal(data, &aux)
	if err == nil {
		b.FixAvailable = aux.Name != ""

		return nil
	}

	return nil
}
