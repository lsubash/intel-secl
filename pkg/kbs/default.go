/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// This init function sets the default values for viper keys.
func init() {
	viper.SetDefault(config.EndpointUrl, constants.DefaultEndpointUrl)
	viper.SetDefault(config.KeyManager, constants.DefaultKeyManager)

	// Set default values for tls
	viper.SetDefault(commConfig.TlsCertFile, constants.DefaultTLSCertPath)
	viper.SetDefault(commConfig.TlsKeyFile, constants.DefaultTLSKeyPath)
	viper.SetDefault(commConfig.TlsCommonName, constants.DefaultKbsTlsCn)
	viper.SetDefault(commConfig.TlsSanList, constants.DefaultKbsTlsSan)

	// Set default values for log
	viper.SetDefault(commConfig.LogEnableStdout, true)
	viper.SetDefault(commConfig.LogLevel, constants.DefaultLogLevel)
	viper.SetDefault(commConfig.LogMaxLength, constants.DefaultLogMaxlength)

	// Set default value for kmip version
	viper.SetDefault(config.KmipVersion, constants.KMIP_2_0)

	// Set default values for server
	viper.SetDefault(commConfig.ServerPort, constants.DefaultKBSListenerPort)
	viper.SetDefault(commConfig.ServerReadTimeout, constants.DefaultReadTimeout)
	viper.SetDefault(commConfig.ServerReadHeaderTimeout, constants.DefaultReadHeaderTimeout)
	viper.SetDefault(commConfig.ServerWriteTimeout, constants.DefaultWriteTimeout)
	viper.SetDefault(commConfig.ServerIdleTimeout, constants.DefaultIdleTimeout)
	viper.SetDefault(commConfig.ServerMaxHeaderBytes, constants.DefaultMaxHeaderBytes)
}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASBaseUrl:       viper.GetString(commConfig.AasBaseUrl),
		CMSBaseURL:       viper.GetString(commConfig.CmsBaseUrl),
		CmsTlsCertDigest: viper.GetString(commConfig.CmsTlsCertSha384),

		EndpointURL: viper.GetString("endpoint-url"),
		KeyManager:  viper.GetString("key-manager"),
		KBS: commConfig.ServiceConfig{
			Username: viper.GetString(config.KBSServiceUsername),
			Password: viper.GetString(config.KBSServicePassword),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString(commConfig.TlsCertFile),
			KeyFile:    viper.GetString(commConfig.TlsKeyFile),
			CommonName: viper.GetString(commConfig.TlsCommonName),
			SANList:    viper.GetString(commConfig.TlsSanList),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
		Server: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		Kmip: config.KmipConfig{
			Version:                   viper.GetString("kmip-version"),
			ServerIP:                  viper.GetString("kmip-server-ip"),
			ServerPort:                viper.GetString("kmip-server-port"),
			Hostname:                  viper.GetString("kmip-hostname"),
			Username:                  viper.GetString("kmip-username"),
			Password:                  viper.GetString("kmip-password"),
			ClientKeyFilePath:         viper.GetString("kmip-client-key-path"),
			ClientCertificateFilePath: viper.GetString("kmip-client-cert-path"),
			RootCertificateFilePath:   viper.GetString("kmip-root-cert-path"),
		},
		Skc: config.SKCConfig{
			StmLabel:          viper.GetString("skc-challenge-type"),
			SQVSUrl:           viper.GetString("sqvs-url"),
			SessionExpiryTime: viper.GetInt("session-expiry-time"),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		commConfig.TlsSanList: "SAN_LIST",
		commConfig.AasBaseUrl: "AAS_API_URL",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
