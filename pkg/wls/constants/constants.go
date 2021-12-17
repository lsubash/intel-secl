/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

// general WLS constants
const (
	ServiceName         = "WLS"
	ExplicitServiceName = "Workload Service"
	ServiceDir          = "wls/"
	OldApiVersion       = "/v1"
	ApiVersion          = "/v2"
	ServiceUserName     = "wls"

	WLSRuntimeUser  = "wls"
	WLSRuntimeGroup = "wls"

	// service remove command
	ServiceRemoveCmd = "systemctl disable wls"

	// Timestamp operations
	ParamDateFormat        = "2006-01-02"
	ParamDateTimeFormat    = "2006-01-02 15:04:05"
	ParamDateTimeFormatUTC = "2006-01-02T15:04:05.000Z"
)

// file and directory constants
const (
	ConfigDir             = "/etc/wls/"
	DefaultConfigFilePath = ConfigDir + "config.yml"
	ConfigFile            = "config"

	// certificates' path
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	TrustedCaCertsDir         = ConfigDir + "certs/trustedca/"
	TrustedKeysDir            = ConfigDir + "trusted-keys/"

	// saml key and cert
	SamlCaCertFilePath = TrustedCaCertsDir + "SamlCaCert.pem"
)

// jwt constants
const (
	JWTCertsCacheTime = "1m"
)

const (
	CertApproverGroupName   = "CertApprover"
	ReportCreationGroupName = "ReportsCreate"
	BearerToken             = "BEARER_TOKEN"
	DefaultKeyCacheSeconds  = 300
	KeyCacheSeconds         = "KEY_CACHE_SECONDS"
)

// log constants
const (
	DefaultLogEntryMaxlength = 1500
)

// server constants
const (
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 10 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
	DefaultWLSListenerPort   = 5000
)

// tls constants
const (
	DefaultWlsTlsCn     = "WLS TLS Certificate"
	DefaultWlsTlsSan    = "127.0.0.1,localhost"
	DefaultKeyAlgorithm = "rsa"
	DefaultKeyLength    = 3072
	// default locations for tls certificate and key
	DefaultTLSKeyFile  = ConfigDir + "tls.key"
	DefaultTLSCertFile = ConfigDir + "tls-cert.pem"
)

// db constants
const (
	DBTypePostgres = "postgres"

	DefaultDbConnRetryAttempts  = 4
	DefaultDbConnRetryTime      = 1
	DefaultSearchResultRowLimit = 10000

	//Postgres connection SslModes
	SslModeAllow      = "allow"
	SslModePrefer     = "prefer"
	SslModeVerifyCa   = "verify-ca"
	SslModeRequire    = "require"
	SslModeVerifyFull = "verify-full"
)

// these are used only when uninstalling service
const (
	HomeDir      = "/opt/" + ServiceDir
	RunDirPath   = "/run/" + ServiceDir
	ExecLinkPath = "/usr/bin/" + ServiceUserName
	LogDir       = "/var/log/" + ServiceDir
)
