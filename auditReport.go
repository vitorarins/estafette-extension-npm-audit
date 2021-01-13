package main

import (
	"encoding/json"

	"github.com/rs/zerolog/log"
)

// AuditReportBody represents the body coming from npm audit
type AuditReportBody struct {
	Actions    []Action         `json:"actions,omitempty"`
	Advisories map[int]Advisory `json:"advisories,omitempty"`
	Metadata   Metadata         `json:"metadata,omitempty"`
	Error      CommandError     `json:"error,omitempty"`
}

type Action struct {
	Action   string    `json:"action,omitempty"`
	Module   string    `json:"module,omitempty"`
	Resolves []Resolve `json:"resolves,omitempty"`
}

type Advisory struct {
	Id       int       `json:"id,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Resolve struct {
	Id  int  `json:"id,omitempty"`
	Dev bool `json:"dev,omitempty"`
}

type Finding struct {
	Version  string `json:"version,omitempty"`
	Optional bool   `json:"optional,omitempty"`
	Bundled  bool   `json:"bundled,omitempty"`
}

type Metadata struct {
	Vulnerabilities      Vulnerabilities `json:"vulnerabilities,omitempty"`
	Dependencies         Dependencies    `json:"dependencies,omitempty"`
	DevDependencies      int             `json:"devDependencies,omitempty"`
	OptionalDependencies int             `json:"optionalDependencies,omitempty"`
	TotalDependencies    int             `json:"totalDependencies,omitempty"`
}

type Vulnerabilities struct {
	Info     int `json:"info,omitempty"`
	Low      int `json:"low,omitempty"`
	Moderate int `json:"moderate,omitempty"`
	High     int `json:"high,omitempty"`
	Critical int `json:"critical,omitempty"`
}

type Dependencies struct {
	Prod         int `json:"prod,omitempty"`
	Dev          int `json:"dev,omitempty"`
	Optional     int `json:"optional,omitempty"`
	Peer         int `json:"peer,omitempty"`
	PeerOptional int `json:"peerOptional,omitempty"`
	Total        int `json:"total,omitempty"`
}

type CommandError struct {
	Code    string `json:"code,omitempty"`
	Summary string `json:"summary,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

func readAuditReport(report string) AuditReportBody {
	var auditReport AuditReportBody
	err := json.Unmarshal([]byte(report), &auditReport)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed unmarshalling audit report")
	}
	return auditReport
}

func (r AuditReportBody) VulnerabilityCount() int {
	return r.Metadata.Vulnerabilities.Critical + r.Metadata.Vulnerabilities.High + r.Metadata.Vulnerabilities.Info + r.Metadata.Vulnerabilities.Low + r.Metadata.Vulnerabilities.Moderate
}
