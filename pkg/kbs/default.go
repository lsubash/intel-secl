/*
 * Copyright (C) 2020 Intel Corporation
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
		CMSBaseURL:       viper.GetString(commConfig.CmsBaseUrl),
		CmsTlsCertDigest: viper.GetString(commConfig.CmsTlsCertSha384),

		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString(commConfig.TlsCertFile),
			KeyFile:    viper.GetString(commConfig.TlsKeyFile),
			CommonName: viper.GetString(commConfig.TlsCommonName),
			SANList:    viper.GetString(commConfig.TlsSanList),
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
