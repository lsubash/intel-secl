/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/spf13/viper"
	"os"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertFile)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyFile)
	viper.SetDefault("tls-common-name", constants.DefaultWlsTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultWlsTlsSan)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")

	// set default values for server
	viper.SetDefault("server-port", constants.DefaultWLSListenerPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)

}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASApiUrl:        viper.GetString("aas-base-url"),
		CMSBaseURL:       viper.GetString("cms-base-url"),
		HVSApiUrl:        viper.GetString("hvs-base-url"),
		CmsTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
		WLS: commConfig.ServiceConfig{
			Username: viper.GetString("wls-service-username"),
			Password: viper.GetString("wls-service-password"),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString("tls-cert-file"),
			KeyFile:    viper.GetString("tls-key-file"),
			CommonName: viper.GetString("tls-common-name"),
			SANList:    viper.GetString("tls-san-list"),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		"tls-san-list":               "SAN_LIST",
		"hvs-base-url":               "HVS_URL",
		"aas-base-url":               "AAS_API_URL",
		"server-read-timeout":        "WLS_SERVER_READ_TIMEOUT",
		"server-read-header-timeout": "WLS_SERVER_READ_HEADER_TIMEOUT",
		"server-write-timeout":       "WLS_SERVER_WRITE_TIMEOUT",
		"server-idle-timeout":        "WLS_SERVER_IDLE_TIMEOUT",
		"server-max-header-bytes":    "WLS_SERVER_MAX_HEADER_BYTES",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
