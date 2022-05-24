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
	viper.SetDefault(commConfig.TlsCertFile, constants.DefaultTLSCertFile)
	viper.SetDefault(commConfig.TlsKeyFile, constants.DefaultTLSKeyFile)
	viper.SetDefault(commConfig.TlsCommonName, constants.DefaultWlsTlsCn)
	viper.SetDefault(commConfig.TlsSanList, constants.DefaultWlsTlsSan)

	// set default values for log
	viper.SetDefault(commConfig.LogMaxLength, constants.DefaultLogEntryMaxlength)
	viper.SetDefault(commConfig.LogEnableStdout, true)
	viper.SetDefault(commConfig.LogLevel, "info")

	// set default values for server
	viper.SetDefault(commConfig.ServerPort, constants.DefaultWLSListenerPort)
	viper.SetDefault(commConfig.ServerReadTimeout, constants.DefaultReadTimeout)
	viper.SetDefault(commConfig.ServerReadHeaderTimeout, constants.DefaultReadHeaderTimeout)
	viper.SetDefault(commConfig.ServerWriteTimeout, constants.DefaultWriteTimeout)
	viper.SetDefault(commConfig.ServerIdleTimeout, constants.DefaultIdleTimeout)
	viper.SetDefault(commConfig.ServerMaxHeaderBytes, constants.DefaultMaxHeaderBytes)

}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASApiUrl:        viper.GetString(commConfig.AasBaseUrl),
		CMSBaseURL:       viper.GetString(commConfig.CmsBaseUrl),
		HVSApiUrl:        viper.GetString(config.HvsBaseUrl),
		CmsTlsCertDigest: viper.GetString(commConfig.CmsTlsCertSha384),
		WLS: commConfig.ServiceConfig{
			Username: viper.GetString(config.WlsServiceUsername),
			Password: viper.GetString(config.WlsServicePassword),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString(commConfig.TlsCertFile),
			KeyFile:    viper.GetString(commConfig.TlsKeyFile),
			CommonName: viper.GetString(commConfig.TlsCommonName),
			SANList:    viper.GetString(commConfig.TlsSanList),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt(commConfig.LogMaxLength),
			EnableStdout: viper.GetBool(commConfig.LogEnableStdout),
			Level:        viper.GetString(commConfig.LogLevel),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		commConfig.TlsSanList:              "SAN_LIST",
		config.HvsBaseUrl:                  "HVS_URL",
		commConfig.AasBaseUrl:              "AAS_API_URL",
		commConfig.ServerReadTimeout:       "WLS_SERVER_READ_TIMEOUT",
		commConfig.ServerReadHeaderTimeout: "WLS_SERVER_READ_HEADER_TIMEOUT",
		commConfig.ServerWriteTimeout:      "WLS_SERVER_WRITE_TIMEOUT",
		commConfig.ServerIdleTimeout:       "WLS_SERVER_IDLE_TIMEOUT",
		commConfig.ServerMaxHeaderBytes:    "WLS_SERVER_MAX_HEADER_BYTES",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
