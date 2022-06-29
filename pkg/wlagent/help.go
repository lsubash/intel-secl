/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wlagent

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/version"
)

const helpStr = `Usage:
	    wlagent <command> [arguments]
	Available Commands:
	    help|-h|--help      Show this help message
	    -v|--version           Print version/build information
	    start                  Start wlagent
	    stop                   Stop wlagent
	    status                 Reports the status of wlagent service
	    fetch-key-url <keyUrl>      Fetch a key from the keyUrl
	    uninstall  [--purge]   Uninstall wlagent. --purge option needs to be applied to remove configuration and secureoverlay2 data files
	    setup [task]           Run setup task
	Available Tasks for setup:
	    download-ca-cert       Download CMS root CA certificate
	    signing-key             Generate a TPM signing key
	    binding-key             Generate a TPM binding key
	    register-signing-key     Register a signing key with the host verification service
	    register-binding-key     Register a binding key with the host verification service
	    update-service-config  Updates service configuration`

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
