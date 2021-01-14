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
	Name         string                          `json:"name,omitempty"`
	Severity     string                          `json:"severity,omitempty"`
	FixAvailable BoolOrVulnerabilityFixAvailable `json:"fixAvailable,omitempty"`
}

type Metadata struct {
	Vulnerabilities MetadataVulnerabilities `json:"vulnerabilities,omitempty"`
	Dependencies    MetadataDependencies    `json:"dependencies,omitempty"`
}

type MetadataVulnerabilities struct {
	Total int `json:"total,omitempty"`
}

type MetadataDependencies struct {
	Prod  int `json:"prod,omitempty"`
	Dev   int `json:"dev,omitempty"`
	Total int `json:"total,omitempty"`
}

type CommandError struct {
	Code    string `json:"code,omitempty"`
	Summary string `json:"summary,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// StringOrStringArray is used to unmarshal/marshal either a single string value or a string array
type BoolOrVulnerabilityFixAvailable struct {
	FixAvailable bool
}

func (b *BoolOrVulnerabilityFixAvailable) UnmarshalJSON(data []byte) error {

	var asBool bool
	err := json.Unmarshal(data, &asBool)
	if err == nil {
		b.FixAvailable = asBool

		return nil
	}

	var aux struct {
		Name          string `json:"name,omitempty"`
		Version       string `json:"version,omitempty"`
		IsSemVerMajor bool   `json:"isSemVerMajor,omitempty"`
	}
	err = json.Unmarshal(data, &aux)
	if err == nil {
		b.FixAvailable = aux.Name != ""

		return nil
	}

	return nil
}
