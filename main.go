package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"runtime"
	"strings"

	"github.com/alecthomas/kingpin"
	foundation "github.com/estafette/estafette-foundation"
	"github.com/rs/zerolog/log"
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
	slackChannels            = kingpin.Flag("channels", "A comma-separated list of Slack channels to send build status to.").Envar("ESTAFETTE_EXTENSION_CHANNELS").String()
	slackWorkspace           = kingpin.Flag("workspace", "A slack workspace.").Envar("ESTAFETTE_EXTENSION_WORKSPACE").String()
	slackCredentialsJSONPath = kingpin.Flag("credentials-path", "Path to file with Slack credentials configured at server level, passed in to this trusted extension.").Default("/credentials/slack_webhook.json").String()

	// git flags
	gitRepoSource = kingpin.Flag("git-repo-source", "The source of the git repository, github.com in this case.").Envar("ESTAFETTE_GIT_SOURCE").Required().String()
	gitRepoOwner  = kingpin.Flag("git-repo-owner", "The owner of the Github/Bitbucket repository.").Envar("ESTAFETTE_GIT_OWNER").Required().String()
	gitRepoName   = kingpin.Flag("git-repo-name", "The repo name of the Github/Bitbucket repository.").Envar("ESTAFETTE_GIT_NAME").Required().String()
)

func main() {

	// parse command line parameters
	kingpin.Parse()

	// init log format from envvar ESTAFETTE_LOG_FORMAT
	foundation.InitLoggingFromEnv(foundation.NewApplicationInfo(appgroup, app, version, branch, revision, buildDate))

	// create context to cancel commands on sigterm
	ctx := foundation.InitCancellationContext(context.Background())

	// get slack webhook client
	// use mounted credential file if present instead of relying on an envvar
	var slackCredentialsJSON string
	if runtime.GOOS == "windows" {
		*slackCredentialsJSONPath = "C:" + *slackCredentialsJSONPath
	}
	if foundation.FileExists(*slackCredentialsJSONPath) {
		log.Info().Msgf("Reading credentials from file at path %v...", *slackCredentialsJSONPath)
		credentialsFileContent, err := ioutil.ReadFile(*slackCredentialsJSONPath)
		if err != nil {
			log.Fatal().Msgf("Failed reading credential file at path %v.", *slackCredentialsJSONPath)
		}
		slackCredentialsJSON = string(credentialsFileContent)
	}

	slackEnabled, slackWebhookClient := getSlackIntegration(*slackChannels, slackCredentialsJSON, *slackWorkspace)

	prodVulnLevel, err := ToLevel(*level)
	if err != nil {
		log.Fatal().Msg("Failed getting vulnerability level for production")
	}

	devVulnLevel, err := ToLevel(*devLevel)
	if err != nil {
		log.Fatal().Msg("Failed getting vulnerability level for development")
	}

	switch *action {
	case "audit":

		// minimal using defaults

		// image: extensions/npm-audit:stable
		// action: audit

		if prodVulnLevel == LevelNone {
			log.Fatal().Msg("level: none is not allowed, needs to be one of low, moderate, high or critical")
		}

		// audit repo
		log.Info().Msg("Auditing repo...\n")
		prodReport, devReport, err := getAuditReport(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed running audit")
		}

		log.Info().Msgf("Checking %v prod dependencies for vulnerabilities with severity higher or equal than %v", prodReport.Metadata.Dependencies.Prod, prodVulnLevel.String())
		if devVulnLevel != LevelNone {
			log.Info().Msgf("Checking %v dev dependencies for vulnerabilities with severity higher or equal than %v", devReport.Metadata.Dependencies.Dev, devVulnLevel.String())
		} else {
			log.Info().Msg("Not checking for vulnerabilities in dev dependencies")
		}

		failBuild, hasPatchableVulnerabilities, err := checkVulnerabilities(prodReport, prodVulnLevel, devReport, devVulnLevel)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed checking audit reports for vulnerabilities")
		}

		if hasPatchableVulnerabilities {
			totalVulnerabilities := 0
			if prodReport != nil {
				totalVulnerabilities += prodReport.Metadata.Vulnerabilities.Total
			}
			if devReport != nil {
				totalVulnerabilities += devReport.Metadata.Vulnerabilities.Total
			}
			reportString := ""
			if totalVulnerabilities > 100 {
				reportString = fmt.Sprintf("There's a total of %v vulnerabilities, not logging them individually; run `npm audit` locally to see them all", totalVulnerabilities)
			} else {
				reportString, err = getAuditReportForLogging(ctx, devVulnLevel)
				if err != nil {
					log.Fatal().Err(err).Msg("Failed running npm audit for logging / slack purposes")
				}
			}

			log.Info().Msg(reportString)

			if slackEnabled {
				// send regularly formatted audit report to slack
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
				log.Fatal().Msg("Failed due to vulnerabilities")
			}
		} else {
			log.Info().Msg("No vulnerabilities in your repository for now. Cheers!")
		}

	default:
		log.Fatal().Err(err).Msg("Set `action: <action>` on this step to audit.")
	}
}

func getAuditReport(ctx context.Context) (prodReport *AuditReport, devReport *AuditReport, err error) {

	prodReport, err = getAuditReportCore(ctx, "--only=prod")
	if err != nil {
		return
	}

	devReport, err = getAuditReportCore(ctx, "--only=dev")
	if err != nil {
		return
	}

	return
}

func getAuditReportCore(ctx context.Context, only string) (auditReport *AuditReport, err error) {

	err = foundation.Retry(func() (retryErr error) {
		output, retryErr := foundation.GetCommandWithArgsOutput(ctx, "npm", []string{"audit", "--json", only})
		if retryErr != nil {
			return
		}
		if output == "" {
			return fmt.Errorf("Output of 'npm audit --json %v' is empty", only)
		}

		retryErr = json.Unmarshal([]byte(output), &auditReport)
		if retryErr != nil {
			return
		}
		if auditReport.Error.Code != "" {
			return fmt.Errorf("Output of 'npm audit --json %v' contains error: %v", only, auditReport.Error)
		}

		return nil
	})
	if err != nil {
		return
	}

	return
}

func checkVulnerabilities(prodReport *AuditReport, prodVulnLevel Level, devReport *AuditReport, devVulnLevel Level) (failBuild, hasPatchableVulnerabilities bool, err error) {

	prodFailBuild, prodHasPatchableVulnerabilities, prodErr := checkVulnerabilitiesCore(prodReport, prodVulnLevel)
	if prodErr != nil {
		return failBuild, hasPatchableVulnerabilities, prodErr
	}

	devFailBuild, devHasPatchableVulnerabilities, devErr := checkVulnerabilitiesCore(devReport, devVulnLevel)
	if prodErr != nil {
		return failBuild, hasPatchableVulnerabilities, devErr
	}

	failBuild = prodFailBuild || devFailBuild
	hasPatchableVulnerabilities = prodHasPatchableVulnerabilities || devHasPatchableVulnerabilities

	return
}

func checkVulnerabilitiesCore(report *AuditReport, vulnLevel Level) (failBuild, hasPatchableVulnerabilities bool, err error) {
	if report == nil {
		return failBuild, hasPatchableVulnerabilities, fmt.Errorf("Report is nil")
	}

	for _, v := range report.Vulnerabilities {
		if !v.FixAvailable {
			continue
		}

		hasPatchableVulnerabilities = true
		if vulnLevel == LevelNone {
			continue
		}

		lvl, innerErr := ToLevel(v.Severity)
		if innerErr != nil {
			return failBuild, hasPatchableVulnerabilities, innerErr
		}
		if lvl >= vulnLevel {
			failBuild = true
		}
	}

	return
}

func getAuditReportForLogging(ctx context.Context, devVulnLevel Level) (reportString string, err error) {

	auditArgs := []string{"audit"}
	if devVulnLevel == LevelNone {
		auditArgs = append(auditArgs, "--only=prod")
	}

	err = foundation.Retry(func() (retryErr error) {
		reportString, retryErr = foundation.GetCommandWithArgsOutput(ctx, "npm", auditArgs)
		if retryErr != nil {
			return
		}
		if reportString == "" {
			return fmt.Errorf("Output of 'npm %v' is empty", strings.Join(auditArgs, " "))
		}

		return nil
	})
	if err != nil {
		return
	}

	return
}

func getSlackIntegration(slackChannels, slackCredentialsJSON, slackWorkspace string) (slackEnabled bool, slackWebhookClient SlackWebhookClient) {
	if slackChannels != "" {
		slackEnabled = true
		var slackCredential *SlackCredentials
		if slackCredentialsJSON != "" && slackWorkspace != "" {
			log.Info().Msg("Unmarshalling Slack credentials...")
			var slackCredentials []SlackCredentials
			err := json.Unmarshal([]byte(slackCredentialsJSON), &slackCredentials)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed unmarshalling Slack credentials")
			}

			log.Info().Msgf("Checking if Slack credential %v exists...", slackWorkspace)
			slackCredential = GetCredentialsByWorkspace(slackCredentials, slackWorkspace)
		} else {
			log.Fatal().Msg("Flags credentials and workspace have to be set")
		}

		if slackCredential == nil {
			log.Fatal().Msgf("Credential with workspace %v does not exist.", slackWorkspace)
		}
		slackWebhook := slackCredential.AdditionalProperties.Webhook
		slackWebhookClient = NewSlackWebhookClient(slackWebhook)
		return
	}
	return
}
