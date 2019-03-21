package main

import (
	"bytes"
	"encoding/json"
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

	// slack flags
	slackWebhookURL      = kingpin.Flag("slack-webhook-url", "A slack webhook url to allow sending messages.").Envar("ESTAFETTE_EXTENSION_SLACK_WEBHOOK").String()
	slackChannels        = kingpin.Flag("slack-channels", "A comma-separated list of Slack channels to send build status to.").Envar("ESTAFETTE_EXTENSION_SLACK_CHANNELS").Required().String()
	slackWorkspace       = kingpin.Flag("slack-workspace", "A slack workspace.").Envar("ESTAFETTE_EXTENSION_SLACK_WORKSPACE").String()
	slackCredentialsJSON = kingpin.Flag("slack-credentials", "Slack credentials configured at server level, passed in to this trusted extension.").Envar("ESTAFETTE_CREDENTIALS_SLACK_WEBHOOK").String()
)

func main() {

	// parse command line parameters
	kingpin.Parse()

	// log to stdout and hide timestamp
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	// log startup message
	log.Printf("Starting estafette-extension-npm-audit version %v...", version)

	// get slack webhook client
	slackEnabled, slackWebhookClient := getSlackIntegration(slackChannels, slackWebhookURL, slackCredentialsJSON, slackWorkspace)

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

		if hasVulns {
			auditArgs = []string{
				"audit",
			}
			reportString, err := runCommand("npm", auditArgs)

			log.Println(reportString)

			// also send report via Slack
			if slackEnabled {
				title := "Vulnerabilities found in your repository."
				// split on comma and loop through channels
				channels := strings.Split(*slackChannels, ",")
				for i := range channels {
					err := slackWebhookClient.SendMessage(channels[i], title, reportString)
					if err != nil {
						log.Printf("Sending status to Slack failed: %v", err)
					}
				}
			}
			if failBuild {
				log.Fatal(err)
			} else {
				log.Println(err)
			}
		} else {
			log.Println("No vulnerabilities in your repository for now. Cheers!")
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

func getSlackIntegration(slackChannels, slackWebhookURL, slackCredentialsJSON, slackWorkspace *string) (slackEnabled bool, slackWebhookClient SlackWebhookClient) {
	if *slackChannels != "" {
		slackEnabled = true
		var slackCredential *SlackCredentials
		if *slackWebhookURL == "" {
			if *slackCredentialsJSON != "" && *slackWorkspace != "" {
				log.Printf("Unmarshalling Slack credentials...")
				var slackCredentials []SlackCredentials
				err := json.Unmarshal([]byte(*slackCredentialsJSON), &slackCredentials)
				if err != nil {
					log.Fatal("Failed unmarshalling Slack credentials: ", err)
				}

				log.Printf("Checking if Slack credential %v exists...", *slackWorkspace)
				slackCredential = GetCredentialsByWorkspace(slackCredentials, *slackWorkspace)
				if slackCredential == nil {
					log.Fatalf("Credential with workspace %v does not exist.", *slackWorkspace)
				}
			} else {
				log.Fatal("Flag slack-webhook-url has to be set")
			}
		}

		slackWebhook := *slackWebhookURL
		if slackCredential != nil {
			slackWebhook = slackCredential.AdditionalProperties.Webhook
		}

		slackWebhookClient = NewSlackWebhookClient(slackWebhook)
		return
	}
	return
}
