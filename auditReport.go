package main

// AuditReport represents the body coming from npm audit
type AuditReport struct {
	AuditReportVersion int                      `json:"auditReportVersion,omitempty"`
	Vulnerabilities    map[string]Vulnerability `json:"vulnerabilities,omitempty"`
	Metadata           Metadata                 `json:"metadata,omitempty"`
	Error              CommandError             `json:"error,omitempty"`
}

type Vulnerability struct {
	Severity     string `json:"severity,omitempty"`
	FixAvailable bool   `json:"fixAvailable,omitempty"`
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
