/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package wpm

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v5/pkg/wpm/version"
)

const helpStr = `
Usage:
    wpm <command> [arguments]

Available Commands:
    -h|--help                        Show this help message
    -v|--version                     Print version/build information
    fetch-key                        Fetches the image encryption key with associated tags from KBS
    uninstall [--purge]              Uninstall wpm. --purge option needs to be applied to remove configuration and data files
    setup                            Run workload-policy-manager setup tasks

Setup command usage:     wpm setup [task] [--force]

Available tasks for setup:
   all                                         Runs all setup tasks
                                               Required env variables:
                                                   - get required env variables from all the setup tasks
                                               Optional env variables:
                                                   - get optional env variables from all the setup tasks

   download-ca-cert                            Download CMS root CA certificate
                                               - Option [--force] overwrites any existing files, and always downloads new root CA cert
                                               Required env variables specific to setup task are:
                                                   - CMS_BASE_URL=<url>                              : for CMS API url
                                                   - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>  : to ensure that WPM is talking to the right CMS instance

   create-envelope-key                           Creates the key pair required to securely transfer key from KBS
                                               - Option [--force] overwrites existing envelope key pairs`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), version.GetVersion())
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

// fetch-key command usage string
func (a *App) printFetchKeyUsage() {
	log.Trace("app:printFetchKeyUsage() Entering")
	defer log.Trace("app:printFetchKeyUsage() Leaving")

	fmt.Fprintf(a.consoleWriter(), "usage: wpm fetch-key [-k key]\n"+
		"\t  -k, --key       (optional) existing key ID\n"+
		"\t                  if not specified, a new key is generated\n"+
		"\t  -t, --asset-tag (optional) asset tags associated with the new key\n"+
		"\t                  tags are key:value separated by comma\n"+
		"\t  -a, --asymmetric (optional) specify to use asymmetric encryption\n"+
		"\t                  currently only supports RSA")
}

// unwrap-key command usage string
func (a *App) printUnwrapKeyUsage() {
	log.Trace("app:printUnwrapKeyUsage() Entering")
	defer log.Trace("app:printUnwrapKeyUsage() Leaving")

	fmt.Fprintf(a.consoleWriter(), "usage: unwrap-key [-i |--in] <wrapped key file path>")
}
