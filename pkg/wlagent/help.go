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
	    help|-help|--help      Show this help message
	    -v|--version           Print version/build information
	    start                  Start wlagent
	    stop                   Stop wlagent
	    status                 Reports the status of wlagent service
	    fetch-key-url <keyUrl>      Fetch a key from the keyUrl
	    uninstall  [--purge]   Uninstall wlagent. --purge option needs to be applied to remove configuration and secureoverlay2 data files
	    setup [task]           Run setup task
	Available Tasks for setup:
	    download-ca-cert       Download CMS root CA certificate
	                           - Option [--force] overwrites any existing files, and always downloads new root CA cert
	                           - Environment variable CMS_BASE_URL=<url> for CMS API url
	                           - Environment variable CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash> to ensure that WLS is talking to the right CMS instance
	    SigningKey             Generate a TPM signing key
	                           - Option [--force] overwrites any existing files, and always creates a new Signing key
	    BindingKey             Generate a TPM binding key
	                           - Option [--force] overwrites any existing files, and always creates a new Binding key
	    RegisterSigningKey     Register a signing key with the host verification service
	                           - Option [--force] Always registers the Signing key with Verification service
	                           - Environment variable HVS_URL=<url> for registering the key with Verification service
	                           - Environment variable BEARER_TOKEN=<token> for authenticating with Verification service
	    RegisterBindingKey     Register a binding key with the host verification service
	                           - Option [--force] Always registers the Binding key with Verification service
	                           - Environment variable HVS_URL=<url> for registering the key with Verification service
	                           - Environment variable BEARER_TOKEN=<token> for authenticating with Verification service
	                           - Environment variable TRUSTAGENT_USERNAME=<TA user> for changing binding key file ownership to TA application user
	    update-service-config  Updates service configuration
	                           - Option [--force] overwrites existing server config
	                           - Environment variable WLS_API_URL=<url> Workload Service URL
	                           - Environment variable WLA_SERVICE_USERNAME WLA Service Username
	                           - Environment variable WLA_SERVICE_PASSWORD WLA Service Password
	                           - Environment variable SKIP_FLAVOR_SIGNATURE_VERIFICATION=<true/false> Skip flavor signature verification if set to true
	                           - Environment variable LOG_ENTRY_MAXLENGTH=Maximum length of each entry in a log
	                           - Environment variable WLA_ENABLE_CONSOLE_LOG=<true/false> Workload Agent Enable standard output`

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
