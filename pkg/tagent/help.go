/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tagent

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v5/pkg/tagent/version"
)

const helpStr = `Usage:

  tagent <command> [arguments]

Available Commands:

  help|-h|-help                    Show this help message.
  setup [all] [task]               Run setup task.
  uninstall                        Uninstall trust agent.
  --version                        Print build version info.
  start                            Start the trust agent service.
  stop                             Stop the trust agent service.
  status                           Get the status of the trust agent service.
  fetch-ekcert-with-issuer         Print Tpm Endorsement Certificate in Base64 encoded string along with issuer
                                   Optional environment variables:
                                   - TPM_OWNER_SECRET=<40 byte hex>                    : When provided, command uses the 40 character hex string for the TPM owner password.
                                                                                         Command uses empty string as owner password when not provided.

Setup command usage:  tagent setup [cmd] [-f <env-file>]

Available Tasks for 'setup', all commands support env file flag

   all                                      - Runs all setup tasks to provision the trust agent. This command can be omitted with running only tagent setup
                                                Required environment variables [in env/trustagent.env]:
                                                  - AAS_API_URL=<url>                                 : AAS API URL
                                                  - CMS_BASE_URL=<url>                                : CMS API URL
                                                  - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that TA is communicating with the right CMS instance
                                                  - BEARER_TOKEN=<token>                              : for authenticating with CMS and VS
                                                  - HVS_URL=<url>                            : VS API URL
                                                Optional Environment variables:
                                                  - TA_ENABLE_CONSOLE_LOG=<true/false>                : When 'true', logs are redirected to stdout. Defaults to false.
                                                  - TA_SERVER_IDLE_TIMEOUT=<t seconds>                : Sets the trust agent service's idle timeout. Defaults to 10 seconds.
                                                  - TA_SERVER_MAX_HEADER_BYTES=<n bytes>              : Sets trust agent service's maximum header bytes.  Defaults to 1MB.
                                                  - TA_SERVER_READ_TIMEOUT=<t seconds>                : Sets trust agent service's read timeout.  Defaults to 30 seconds.
                                                  - TA_SERVER_READ_HEADER_TIMEOUT=<t seconds>         : Sets trust agent service's read header timeout.  Defaults to 30 seconds.
                                                  - TA_SERVER_WRITE_TIMEOUT=<t seconds>               : Sets trust agent service's write timeout.  Defaults to 10 seconds.
                                                  - SAN_LIST=<host1,host2.acme.com,...>               : CSV list that sets the value for SAN list in the TA TLS certificate.
                                                                                                        Defaults to "127.0.0.1,localhost".
                                                  - TA_TLS_CERT_CN=<Common Name>                      : Sets the value for Common Name in the TA TLS certificate.  Defaults to "Trust Agent TLS Certificate".
                                                  - TPM_OWNER_SECRET=<40 byte hex>                    : When provided, setup uses the 40 character hex string for the TPM
                                                                                                        owner password. Auto-generated when not provided.
                                                  - TRUSTAGENT_LOG_LEVEL=<trace|debug|info|error>     : Sets the verbosity level of logging. Defaults to 'info'.
                                                  - TRUSTAGENT_PORT=<portnum>                         : The port on which the trust agent service will listen.
                                                                                                        Defaults to 1443
                                                  - NATS_SERVERS                                      : Comma-separated list of NATs servers


  download-ca-cert                          - Fetches the latest CMS Root CA Certificates, overwriting existing files.
                                                    Required environment variables:
                                                       - CMS_BASE_URL=<url>                                : CMS API URL
                                                       - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that TA is communicating with the right CMS instance
        
  download-cert                             - Fetches a signed TLS Certificate from CMS, overwriting existing files.
                                                    Required environment variables:
                                                       - CMS_BASE_URL=<url>                                : CMS API URL
                                                       - BEARER_TOKEN=<token>                              : for authenticating with CMS and VS
                                                    Optional Environment variables:
                                                       - SAN_LIST=<host1,host2.acme.com,...>               : CSV list that sets the value for SAN list in the TA TLS certificate.
                                                                                                             Defaults to "127.0.0.1,localhost".
                                                       - TA_TLS_CERT_CN=<Common Name>                      : Sets the value for Common Name in the TA TLS certificate.
                                                                                                             Defaults to "Trust Agent TLS Certificate".
  download-credential                       - Fetches Credential from AAS
                                                    Required environment variables:
                                                       - BEARER_TOKEN=<token>                              : for authenticating with AAS
                                                       - AAS_API_URL=<url>                                 : AAS API URL
                                                       - TA_HOST_ID=<ta-host-id>                           : FQDN of host
  download-api-token                        - Fetches Custom Claims Token from AAS
                                                    Required environment variables:
                                                       - BEARER_TOKEN=<token>                              : for authenticating with AAS
                                                       - AAS_API_URL=<url>                                 : AAS API URL
  update-certificates                       - Runs 'download-ca-cert' and 'download-cert'
                                                    Required environment variables:
                                                       - CMS_BASE_URL=<url>                                : CMS API URL
                                                       - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that TA is communicating with the right CMS instance
                                                       - BEARER_TOKEN=<token>                              : for authenticating with CMS
                                                    Optional Environment variables:
                                                       - SAN_LIST=<host1,host2.acme.com,...>               : CSV list that sets the value for SAN list in the TA TLS certificate.
                                                                                                              Defaults to "127.0.0.1,localhost".
                                                       - TA_TLS_CERT_CN=<Common Name>                      : Sets the value for Common Name in the TA TLS certificate.  Defaults to "Trust Agent TLS Certificate".

  provision-attestation                     - Runs setup tasks associated with HVS/TPM provisioning.
                                                    Required environment variables:
                                                        - HVS_URL=<url>                            : VS API URL
                                                        - BEARER_TOKEN=<token>                              : for authenticating with VS
                                                    Optional environment variables:
                                                        - TPM_OWNER_SECRET=<40 byte hex>                    : When provided, setup uses the 40 character hex string for the TPM
                                                                                                              owner password. Setup uses empty string when not provided.

  create-host                                 - Registers the trust agent with the verification service.
                                                    Required environment variables:
                                                        - HVS_URL=<url>                            : VS API URL
                                                        - BEARER_TOKEN=<token>                              : for authenticating with VS
                                                        - CURRENT_IP=<ip address of host>                   : IP or hostname of host with which the host will be registered with HVS
                                                    Optional environment variables:
                                                        - TPM_OWNER_SECRET=<40 byte hex>                    : When provided, setup uses the 40 character hex string for the TPM
                                                                                                              owner password. Setup uses empty when not provided.

  create-host-unique-flavor                 - Populates the verification service with the host unique flavor
                                                    Required environment variables:
                                                        - HVS_URL=<url>                            : VS API URL
                                                        - BEARER_TOKEN=<token>                              : for authenticating with VS
                                                        - CURRENT_IP=<ip address of host>                   : Used to associate the flavor with the host

  get-configured-manifest                   - Uses environment variables to pull application-integrity 
                                              manifests from the verification service.
                                                     Required environment variables:
                                                        - HVS_URL=<url>                            : VS API URL
                                                        - BEARER_TOKEN=<token>                              : for authenticating with VS
                                                        - FLAVOR_UUIDS=<uuid1,uuid2,[...]>                  : CSV list of flavor UUIDs
                                                        - FLAVOR_LABELS=<flavorlabel1,flavorlabel2,[...]>   : CSV list of flavor labels                                                   
  update-service-config                     - Updates service configuration  
                                                     Required environment variables:
                                                        - TRUSTAGENT_PORT=<port>                            : Trust Agent Listener Port
                                                        - TA_SERVER_READ_TIMEOUT                            : Trustagent Server Read Timeout
                                                        - TA_SERVER_READ_HEADER_TIMEOUT                     : Trustagent Read Header Timeout
                                                        - TA_SERVER_WRITE_TIMEOUT                           : Tustagent Write Timeout                                                   
                                                        - TA_SERVER_IDLE_TIMEOUT                            : Trustagent Idle Timeout                                                    
                                                        - TA_SERVER_MAX_HEADER_BYTES                        : Trustagent Max Header Bytes Timeout                                                    
                                                        - TRUSTAGENT_LOG_LEVEL                              : Logging Level                                                    
                                                        - TA_ENABLE_CONSOLE_LOG                             : Trustagent Enable standard output                                                    
                                                        - LOG_ENTRY_MAXLENGTH                               : Maximum length of each entry in a log
														- NATS_SERVERS                                      : Comma-separated list of NATs servers",
  define-tag-index                          - Allocates nvram in the TPM for use by asset tags.`

func (app *App) printUsage() {
	fmt.Fprintln(app.consoleWriter(), helpStr)
}

func (app *App) printUsageWithError(err error) {
	fmt.Fprintln(app.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(app.errorWriter(), helpStr)
}

func (app *App) printVersion() {
	fmt.Fprintf(app.consoleWriter(), version.GetVersion())
}
