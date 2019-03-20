package main

import (
	"bytes"
	"github.com/alecthomas/kingpin"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var (
	version   string
	branch    string
	revision  string
	buildDate string
	goVersion = runtime.Version()
)

var (
	// flags
	action   = kingpin.Flag("action", "Any of the following actions: audit.").Envar("ESTAFETTE_EXTENSION_ACTION").String()
	level    = kingpin.Flag("level", "Level of security you want to check for. It can be: low, moderate, high or critical.").Default("low").OverrideDefaultFromEnvar("ESTAFETTE_EXTENSION_LEVEL").String()
	devLevel = kingpin.Flag("dev-level", "Level of security you want to check for your Dev dependencies. It can be: low, moderate, high, critical or none.").Default("low").OverrideDefaultFromEnvar("ESTAFETTE_EXTENSION_DEV_LEVEL").String()
)

func main() {

	// parse command line parameters
	kingpin.Parse()

	// log to stdout and hide timestamp
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	// log startup message
	log.Printf("Starting estafette-extension-npm-audit version %v...", version)

	prodVulnLevel, err := VulnLevel(*level)
	if err != nil {
		log.Println(err)
	}

	devVulnLevel, err := VulnLevel(*devLevel)
	if err != nil {
		log.Println(err)
	}
	switch *action {
	case "audit":

		// minimal using defaults

		// image: extensions/npm-audit:stable
		// action: audit

		// audit repo
		log.Printf("Auditing repo...\n")
		auditArgs := []string{
			"audit",
			"--json",
		}
		reportJson, err := runCommand("npm", auditArgs)
		if err != nil {
			log.Println(err)
		}

		auditReport := readAuditReport(reportJson)

		log.Printf("Checking for %v vulnerabilities on production repositories\n", prodVulnLevel.String())
		log.Printf("Checking for %v vulnerabilities on dev dependencies repositories\n", devVulnLevel.String())
		failBuild, hasVulns := checkVulnerabilities(auditReport, prodVulnLevel, devVulnLevel)
		auditArgs = []string{
			"audit",
		}
		reportString, err := runCommand("npm", auditArgs)
		if failBuild && err != nil {
			log.Println(reportString)
			log.Fatal(err)
		} else {
			if hasVulns {
				// TODO: send report via Slack
				log.Println(reportString)
				if err != nil {
					log.Println(err)
				}
			} else {
				log.Println("No vulnerabilities in your repository for now. Cheers!")
			}
		}
	default:
		log.Fatal("Set `action: <action>` on this step to audit.")
	}
}

func runCommand(command string, args []string) (string, error) {
	log.Printf("Running command '%v %v'...", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	cmd.Dir = "/estafette-work"
	var outb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return outb.String(), err
}

func isCheckEnabled(level Level, levelString string) bool {
	checkLevel, err := VulnLevel(levelString)
	if err != nil {
		log.Println(err)
	}
	return level <= checkLevel
}

func checkVulnerabilities(auditReport AuditReportBody, prodVulnLevel, devVulnLevel Level) (failBuild, hasVulnerabilities bool) {
	failBuild = false
	hasVulnerabilities = false
	for _, advisory := range auditReport.Advisories {
		hasVulnerabilities = true
		severity := advisory.Severity
		for _, finding := range advisory.Findings {
			if finding.Dev {
				failBuild = isCheckEnabled(devVulnLevel, severity)
			} else {
				failBuild = isCheckEnabled(prodVulnLevel, severity)
			}
			if failBuild {
				return
			}
		}
	}
	return
}
