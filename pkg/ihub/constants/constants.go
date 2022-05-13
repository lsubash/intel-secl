/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	ServiceName                 = "ihub"
	InstancePrefix              = "ihub@"
	ExplicitServiceName         = "Integration Hub"
	PollingIntervalMinutes      = 2
	HomeDir                     = "/opt/ihub/"
	SysConfigDir                = "/etc/"
	ConfigDir                   = "/etc/ihub/"
	DefaultConfigFilePath       = "config.yml"
	ExecLinkPath                = "/usr/bin/ihub"
	RunDirPath                  = "/run/ihub"
	SysLogDir                   = "/var/log/"
	LogDir                      = "/var/log/ihub/"
	ConfigFile                  = "config"
	DefaultTLSCertFile          = "tls-cert.pem"
	DefaultTLSKeyFile           = "tls-key.pem"
	PublicKeyLocation           = "ihub_public_key.pem"
	PrivateKeyLocation          = "ihub_private_key.pem"
	TrustedCAsStoreDir          = "certs/trustedca/"
	SamlCertFilePath            = "certs/saml/saml-cert.pem"
	ServiceRemoveCmd            = "systemctl disable "
	DefaultKeyAlgorithm         = "rsa"
	DefaultKeyLength            = 3072
	DefaultTLSSan               = "127.0.0.1,localhost"
	DefaultIHUBTlsCn            = "Integration Hub TLS Certificate"
	K8sTenant                   = "KUBERNETES"
	HTTP                        = "http"
	KubernetesNodesAPI          = "api/v1/nodes"
	KubernetesCRDAPI            = "apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/"
	KubernetesCRDAPIVersion     = "crd.isecl.intel.com/v1beta1"
	KubernetesCRDKind           = "HostAttributesCrd"
	KubernetesMetaDataNameSpace = "default"
	KubernetesCRDName           = "custom-isecl"
	DefaultK8SCertFile          = "apiserver.crt"
	RegexNonStandardChar        = "[^a-zA-Z0-9]"
	DefaultLogEntryMaxlength    = 1500
	MaxArguments                = 5
)

const (
	RegexEpcSize = `[[:digit:]]+(\.[[:digit:]]+)? [KMGT]?B`
)
