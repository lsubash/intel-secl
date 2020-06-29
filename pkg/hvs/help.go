package hvs

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/version"
)

const helpStr = `Usage:
	hvs <command> [arguments]
	
Avaliable Commands:
	help|-h|--help         Show this help message
	version|-v|--version   Show the version of current hvs build
	setup <task>           Run setup task
	start                  Start hvs
	status                 Show the status of hvs
	stop                   Stop hvs
	uninstall [--purge]    Uninstall hvs
		--purge            all configuration and data files will be removed if this flag is set

Usage of hvs setup:
	hvs setup <task> [--force] [-f <answer-file>]
		--force                     existing configuration will e overwritten if this flag is set
		-f|--file <answer-file>     the answer file with required arguments

Available Tasks for setup:
	all                             Runs all setup tasks
	server                          Setup http server on given port
	database                        Setup hvs database
	download-ca-cert                Download CMS root CA certificate
	download-cert-tls               Download CA certificate from CMS for tls
	download-cert-saml              Download CA certificate from CMS for saml
	download-cert-flavor-signing    Download CA certificate from CMS for flavor signing
	create-endorsement-ca           Generate self-signed endorsement certificate
	create-privacy-ca               Generate self-signed privacy certificate
	create-tag-ca                   Generate self-signed tag certificate
`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), "Host Verification Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
}