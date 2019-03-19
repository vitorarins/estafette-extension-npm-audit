package main

import (
	"fmt"
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
	action = kingpin.Flag("action", "Any of the following actions: audit.").Envar("ESTAFETTE_EXTENSION_ACTION").String()
	level  = kingpin.Flag("level", "Level of security you want to check for. It can be: info, low, moderate, high or critical.").Envar("ESTAFETTE_EXTENSION_LEVEL").String()
)

func main() {

	// parse command line parameters
	kingpin.Parse()

	// log to stdout and hide timestamp
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	// log startup message
	log.Printf("Starting estafette-extension-npm-audit version %v...", version)

	var levelString string
	if *level != "" {
		levelString = *level
	} else {
		levelString = "low"
	}
	switch *action {
	case "audit":

		// minimal using defaults

		// image: extensions/npm-audit:stable
		// action: audit
		// level: critical

		// audit repo
		log.Printf("Auditing repo...\n")
		auditArgs := []string{
			"audit",
			fmt.Sprintf("--audit-level=%v", levelString),
		}
		runCommand("npm", auditArgs)

	default:
		log.Fatal("Set `action: <action>` on this step to audit.")
	}
}

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func runCommand(command string, args []string) {
	log.Printf("Running command '%v %v'...", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	cmd.Dir = "/estafette-work"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	handleError(err)
}
