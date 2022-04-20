/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	ServiceName         = "WPM"
	ExtendedServiceName = "Workload Policy Manager"
	ServiceDir          = "wpm/"
	ServiceUserName     = "wpm"

	HomeDir               = "/opt/" + ServiceDir
	ExecLinkPath          = "/usr/bin/" + ServiceUserName
	LogDir                = "/var/log/" + ServiceDir
	ConfigDir             = "/etc/" + ServiceDir
	ConfigFile            = "config"
	DefaultConfigFilePath = ConfigDir + "config.yml"

	// certificates' path
	TrustedCaCertsDir = ConfigDir + "certs/trustedca/"
	EnvelopekeyDir    = ConfigDir + "certs/kbs/"

	EnvelopePublickeyLocation  = EnvelopekeyDir + "envelopePublicKey.pub"
	EnvelopePrivatekeyLocation = EnvelopekeyDir + "envelopePrivateKey.pem"

	//log config
	DefaultLogLevel     = "info"
	DefaultLogMaxlength = 1500

	// create key parameters
	KbsEncryptAlgo            = "AES"
	KbsKeyLength              = 256
	DefaultKeyAlgorithm       = "rsa"
	DefaultKeyAlgorithmLength = 3072

	OcicryptKeyProviderName     = "isecl"
	OcicryptKeyProviderAssetTag = "asset-tag"
	OcicryptKeyProviderKeyId    = "key-id"
)
