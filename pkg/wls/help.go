/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v5/pkg/wls/version"
)

const helpStr = `Usage:
    wls <command> [arguments]

Available Commands:
    -h|--help            Show this help message
    -v|--version         Print version/build information
    start                Start wls
    stop                 Stop wls
    status               Determine if wls is running
    uninstall [--purge]  Uninstall wls. --purge option needs to be applied to remove configuration and data files
    setup                Run workload-service setup tasks

Setup command usage:     wls setup [task] [--force]

Available tasks for setup:
   all                              Runs all setup tasks
   download-ca-cert                 Download CMS root CA certificate
   download-cert-tls                Generates Key pair and CSR, gets it signed from CMS
   database                         Setup workload-service database
   server                           Setup http server on given port
   hvs-connection                   Setup task for setting up the connection to the Host Verification Service(HVS)
   download-saml-ca-cert            Setup to download SAML CA certificates from HVS
   update-service-config            Sets or Updates the Service configuration 
`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), version.GetVersion())
}
