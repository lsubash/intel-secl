/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"path"
)

const (
	LogDir           = "/var/log/workload-agent/"
	DefaultFilePerms = 0600
)

var (
	DefaultLogFilePath  = path.Join(LogDir, "workload-agent.log")
	SecurityLogFilePath = path.Join(LogDir, "workload-agent-security.log")
)

// Env var names for setup
const (
	HvsUrlEnv                 = "HVS_URL"
	WlsApiUrlEnv              = "WLS_API_URL"
	WlaUsernameEnv            = "WLA_SERVICE_USERNAME"
	WlaPasswordEnv            = "WLA_SERVICE_PASSWORD"
	AasUrlEnv                 = "AAS_API_URL"
	BearerTokenEnv            = "BEARER_TOKEN"
	LogLevelEnvVar            = "LOG_LEVEL"
	LogEntryMaxlengthEnv      = "LOG_ENTRY_MAXLENGTH"
	EnableConsoleLogEnv       = "WLA_ENABLE_CONSOLE_LOG"
	TAUserNameEnv             = "TRUSTAGENT_USERNAME"
	SkipFlavorSignatureVerEnv = "SKIP_FLAVOR_SIGNATURE_VERIFICATION"
	CmsTlsCertSha384Env       = "CMS_TLS_CERT_SHA384"
)

// viper key strings
const (
	HvsApiUrlViperKey                       = "hvs.api-url"
	SkipFlavorSignatureVerificationViperKey = "skip-flavor-signature-verification"
	BindingKeySecretViperKey                = "binding-key-secret"
	SigningKeySecretViperKey                = "signing-key-secret"
	WlsApiUrlViperKey                       = "wls.api-url"
	WlaUsernameViperKey                     = "wla.api-user-name"
	WlaPasswordViperKey                     = "wla.api-password"
	AasBaseUrlViperKey                      = "aas.base-url"
	CmsBaseUrlViperKey                      = "cms.base-url"
	CmsTlsCertDigestViperKey                = "cms.tls-sha384"
	LogStdoutViperKey                       = "log.enable-stdout"
	LogMaxLengthViperKey                    = "log.max-length"
	LogLevelViperKey                        = "log.level"
	TaConfigDirViperKey                     = "trustagent.config-dir"
	TaAikPemFileViperKey                    = "trustagent.aik-pem-file"
	TaUserViperKey                          = "trustagent.user"
	ViperKeyDashSeparator                   = "-"
	ViperDotSeparator                       = "."
	EnvNameSeparator                        = "_"
)

const (
	ExplicitServiceName         = "Workload Agent"
	DefaultLogEntryMaxlength    = 3000
	DefaultLogLevel             = "info"
	TAAikPemFileName            = "aik.pem"
	BindingKeyFileName          = "bindingkey.json"
	SigningKeyFileName          = "signingkey.json"
	BindingKeyPemFileName       = "bindingkey.pem"
	BindingKeyType              = "binding"
	SigningKeyType              = "signing"
	SigningKeyPemFileName       = "signingkey.pem"
	LogDirPath                  = "/var/log/workload-agent/"
	ConfigFileName              = "config"
	ConfigFileExtension         = "yml"
	ConfigDirPath               = "/etc/workload-agent/"
	OptDirPath                  = "/opt/workload-agent/"
	RunDirPath                  = "/var/run/workload-agent/"
	RPCSocketFileName           = "wlagent.sock"
	WlagentSymLink              = "/usr/local/bin/wlagent"
	PemCertificateHeader        = "CERTIFICATE"
	ServiceUserName             = "wlagent"
	TrustedCaCertsDir           = ConfigDirPath + "certs/trustedca/"
	DefaultConfigFilePath       = ConfigDirPath + ConfigFileName + "." + ConfigFileExtension
	DefaultTrustagentUser       = "tagent"
	DefaultTrustagentConfigPath = "/etc/trustagent"
	SystemCtlCmd                = "systemctl"
	SystemctlStartOperation     = "start"
	SystemctlStopOperation      = "stop"
	SystemctlStatusOperation    = "status"
	SystemctlDisableOperation   = "disable"
	SystemdServiceName          = "wlagent"
	WlsKeysEndPoint             = "/keys"
)

// Task Names
const (
	SetupAllCommand            = "all"
	DownloadRootCACertCommand  = "download-ca-cert"
	RegisterSigningKeyCommand  = "register-signing-key"
	RegisterBindingKeyCommand  = "register-binding-key"
	UpdateServiceConfigCommand = "update-service-config"
	CreateBindingKey           = "binding-key"
	CreateSigningKey           = "signing-key"
)

// application constants(
const (
	TpmVersion12 = "1.2"
	TpmVersion20 = "2.0"
)
