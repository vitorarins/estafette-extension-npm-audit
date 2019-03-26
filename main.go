package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/alecthomas/kingpin"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
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
	slackChannels        = kingpin.Flag("channels", "A comma-separated list of Slack channels to send build status to.").Envar("ESTAFETTE_EXTENSION_CHANNELS").String()
	slackWorkspace       = kingpin.Flag("workspace", "A slack workspace.").Envar("ESTAFETTE_EXTENSION_WORKSPACE").String()
	slackCredentialsJSON = kingpin.Flag("credentials", "Slack credentials configured at server level, passed in to this trusted extension.").Envar("ESTAFETTE_CREDENTIALS_SLACK_WEBHOOK").String()

	// git flags
	gitRepoSource = kingpin.Flag("git-repo-source", "The source of the git repository, github.com in this case.").Envar("ESTAFETTE_GIT_SOURCE").Required().String()
	gitRepoOwner  = kingpin.Flag("git-repo-owner", "The owner of the Github/Bitbucket repository.").Envar("ESTAFETTE_GIT_OWNER").Required().String()
	gitRepoName   = kingpin.Flag("git-repo-name", "The repo name of the Github/Bitbucket repository.").Envar("ESTAFETTE_GIT_NAME").Required().String()
)

var random *rand.Rand

func init() {
	random = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func main() {

	// parse command line parameters
	kingpin.Parse()

	// log to stdout and hide timestamp
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	// log startup message
	log.Printf("Starting estafette-extension-npm-audit version %v...", version)

	// get slack webhook client
	slackEnabled, slackWebhookClient := getSlackIntegration(slackChannels, slackCredentialsJSON, slackWorkspace)

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
		auditReport, err := retryGetReport()
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Checking %v dependencies for vulnerabilities with severity higher or equal than %v", auditReport.Metadata.Dependencies, prodVulnLevel.String())
		if devVulnLevel != None {
			log.Printf("Checking %v dev dependencies for vulnerabilities with severity higher or equal than %v", auditReport.Metadata.DevDependencies, devVulnLevel.String())
		} else {
			log.Printf("Not checking for vulnerabilities in dev dependencies")
		}

		failBuild, hasVulns := checkVulnerabilities(auditReport, prodVulnLevel, devVulnLevel)

		if hasVulns {
			auditArgs := []string{
				"audit",
			}
			reportString, err := retryCommand("npm", auditArgs)

			log.Println(reportString)

			// also send report via Slack
			if slackEnabled {
				titleLink := fmt.Sprintf("https://%v/%v/%v", *gitRepoSource, *gitRepoOwner, *gitRepoName)
				title := fmt.Sprintf("Vulnerabilities found in your repository: %v", *gitRepoName)
				// split on comma and loop through channels
				channels := strings.Split(*slackChannels, ",")
				for i := range channels {
					err := slackWebhookClient.SendMessage(channels[i], title, titleLink, reportString)
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

func retryCommand(command string, args []string) (out string, err error) {
	for i := 1; i <= 3; i++ {
		out, err = runCommand(command, args)
		if out == "" && err != nil {
			time.After(jitter(i) + 1*time.Microsecond)
		} else {
			return
		}
	}
	return
}

func retryGetReport() (auditReport AuditReportBody, err error) {
	auditArgs := []string{
		"audit",
		"--json",
	}
	var out string
	for i := 1; i <= 3; i++ {
		out, err = runCommand("npm", auditArgs)
		if out == "" {
			time.After(jitter(i) + 1*time.Microsecond)
		} else {
			auditReport = readAuditReport(out)
			if auditReport.Error.Code != "" {
				time.After(jitter(i) + 1*time.Microsecond)
			} else {
				return
			}
		}
	}
	return
}

func jitter(i int) time.Duration {
	i = int(1 << uint(i))
	ms := i * 1000

	maxJitter := ms / 3

	// ms ± rand
	ms += random.Intn(2*maxJitter) - maxJitter

	// a jitter of 0 messes up the time.Tick chan
	if ms <= 0 {
		ms = 1
	}

	return time.Duration(ms) * time.Millisecond
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

func getSlackIntegration(slackChannels, slackCredentialsJSON, slackWorkspace *string) (slackEnabled bool, slackWebhookClient SlackWebhookClient) {
	if *slackChannels != "" {
		slackEnabled = true
		var slackCredential *SlackCredentials
		if *slackCredentialsJSON != "" && *slackWorkspace != "" {
			log.Printf("Unmarshalling Slack credentials...")
			var slackCredentials []SlackCredentials
			err := json.Unmarshal([]byte(*slackCredentialsJSON), &slackCredentials)
			if err != nil {
				log.Fatal("Failed unmarshalling Slack credentials: ", err)
			}

			log.Printf("Checking if Slack credential %v exists...", *slackWorkspace)
			slackCredential = GetCredentialsByWorkspace(slackCredentials, *slackWorkspace)
		} else {
			log.Fatal("Flags credentials and workspace have to be set")
		}

		if slackCredential == nil {
			log.Fatalf("Credential with workspace %v does not exist.", *slackWorkspace)
		}
		slackWebhook := slackCredential.AdditionalProperties.Webhook
		slackWebhookClient = NewSlackWebhookClient(slackWebhook)
		return
	}
	return
}
