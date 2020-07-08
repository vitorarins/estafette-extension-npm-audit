package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"time"

	"github.com/alecthomas/kingpin"
	foundation "github.com/estafette/estafette-foundation"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

var (
	appgroup  string
	app       string
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

	// init log format from envvar ESTAFETTE_LOG_FORMAT
	foundation.InitLoggingFromEnv(foundation.NewApplicationInfo(appgroup, app, version, branch, revision, buildDate))

	// create context to cancel commands on sigterm
	ctx := foundation.InitCancellationContext(context.Background())

	// get slack webhook client
	slackEnabled, slackWebhookClient := getSlackIntegration(slackChannels, slackCredentialsJSON, slackWorkspace)

	prodVulnLevel, err := VulnLevel(*level)
	if err != nil {
		log.Info().Msg("Failed getting vulnerability level for production")
	}

	devVulnLevel, err := VulnLevel(*devLevel)
	if err != nil {
		log.Info().Msg("Failed getting vulnerability level for development")
	}
	switch *action {
	case "audit":

		// minimal using defaults

		// image: extensions/npm-audit:stable
		// action: audit

		// audit repo
		log.Info().Msg("Auditing repo...\n")
		auditReport, err := retryGetReport(ctx, devVulnLevel)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed running audit")
		}

		log.Info().Msgf("Checking %v dependencies for vulnerabilities with severity higher or equal than %v", auditReport.Metadata.Dependencies, prodVulnLevel.String())
		if devVulnLevel != None {
			log.Info().Msgf("Checking %v dev dependencies for vulnerabilities with severity higher or equal than %v", auditReport.Metadata.DevDependencies, devVulnLevel.String())
		} else {
			log.Info().Msg("Not checking for vulnerabilities in dev dependencies")
		}

		failBuild, hasVulns := checkVulnerabilities(auditReport, prodVulnLevel, devVulnLevel)

		if hasVulns {

			vulnerabilityCount := auditReport.VulnerabilityCount()
			reportString := fmt.Sprintf("There's a total of %v vulnerabilities, not logging them individually; run `npm audit` locally to see them all", vulnerabilityCount)
			if vulnerabilityCount < 25 {
				reportString, err = retryCommand(ctx, "npm", []string{
					"audit",
				})
			}
			log.Info().Msg(reportString)

			// also send report via Slack
			if slackEnabled {
				titleLink := fmt.Sprintf("https://%v/%v/%v", *gitRepoSource, *gitRepoOwner, *gitRepoName)
				title := fmt.Sprintf("Vulnerabilities found in your repository: %v", *gitRepoName)
				// split on comma and loop through channels
				channels := strings.Split(*slackChannels, ",")
				for i := range channels {
					err := slackWebhookClient.SendMessage(channels[i], title, titleLink, reportString)
					if err != nil {
						log.Info().Msgf("Sending status to Slack failed: %v", err)
					}
				}
			}
			if failBuild {
				log.Fatal().Msg("Failed checking vulnerabilities")
			}
		} else {
			log.Info().Msg("No vulnerabilities in your repository for now. Cheers!")
		}
	default:
		log.Fatal().Err(err).Msg("Set `action: <action>` on this step to audit.")
	}
}

func retryCommand(ctx context.Context, command string, args []string) (out string, err error) {
	out, err = foundation.GetCommandWithArgsOutput(ctx, command, args)
	if out == "" && err != nil {
		for i := 1; i <= 3; i++ {

			time.Sleep(jitter(i) + 1*time.Microsecond)
			out, err = foundation.GetCommandWithArgsOutput(ctx, command, args)
			if out != "" && err == nil {
				return
			}
		}
	}
	return
}

func retryGetReport(ctx context.Context, devVulnLevel Level) (auditReport AuditReportBody, err error) {
	auditArgs := []string{
		"audit",
		"--json",
	}
	if devVulnLevel == None {
		auditArgs = append(auditArgs, "--production")
	}
	var out string
	out, err = foundation.GetCommandWithArgsOutput(ctx, "npm", auditArgs)

	shouldRetry := false
	if out == "" {
		shouldRetry = true
	} else {
		auditReport = readAuditReport(out)
		if auditReport.Error.Code != "" {
			shouldRetry = true
		}
	}

	if shouldRetry {
		for i := 1; i <= 3; i++ {
			time.Sleep(jitter(i) + 1*time.Microsecond)
			out, err = foundation.GetCommandWithArgsOutput(ctx, "npm", auditArgs)
			if out != "" {
				auditReport = readAuditReport(out)
				if auditReport.Error.Code == "" {
					// if we get the output and got the report without errors, don't throw err
					if err != nil {
						log.Info().Msgf("%v", err)
						err = nil
					}
					return
				}
			}
		}
	}

	// if we get the output and got the report without errors, don't throw err
	if err != nil && auditReport.Error.Code == "" {
		log.Info().Msgf("%v", err)
		err = nil
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
		log.Info().Msgf("%v", err)
	}
	return level <= checkLevel
}

func checkVulnerabilities(auditReport AuditReportBody, prodVulnLevel, devVulnLevel Level) (failBuild, hasPatchableVulnerabilities bool) {
	failBuild = false
	hasPatchableVulnerabilities = false
	for _, advisory := range auditReport.Advisories {
		devVulnerability := false
		severity := advisory.Severity
		for _, action := range auditReport.Actions {
			for _, resolve := range action.Resolves {
				if resolve.Id == advisory.Id {
					devVulnerability = resolve.Dev
					if action.Action != "review" {
						hasPatchableVulnerabilities = true
					}
				}
			}
		}

		if hasPatchableVulnerabilities {
			if devVulnerability {
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
			log.Info().Msg("Unmarshalling Slack credentials...")
			var slackCredentials []SlackCredentials
			err := json.Unmarshal([]byte(*slackCredentialsJSON), &slackCredentials)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed unmarshalling Slack credentials")
			}

			log.Info().Msgf("Checking if Slack credential %v exists...", *slackWorkspace)
			slackCredential = GetCredentialsByWorkspace(slackCredentials, *slackWorkspace)
		} else {
			log.Fatal().Msg("Flags credentials and workspace have to be set")
		}

		if slackCredential == nil {
			log.Fatal().Msgf("Credential with workspace %v does not exist.", *slackWorkspace)
		}
		slackWebhook := slackCredential.AdditionalProperties.Webhook
		slackWebhookClient = NewSlackWebhookClient(slackWebhook)
		return
	}
	return
}

func generateReport(actions []Action) string {
	output, err := yaml.Marshal(actions)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed converting actions into yaml")
	}

	return string(output)
}
