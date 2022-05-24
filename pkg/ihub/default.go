/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ihub

import (
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/constants"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// This func sets the default values for viper keys
func init() {
	viper.SetDefault(config.PollIntervalMinutes, constants.PollingIntervalMinutes)

	//Set default values for TLS
	viper.SetDefault(commConfig.TlsCertFile, constants.ConfigDir+constants.DefaultTLSCertFile)
	viper.SetDefault(commConfig.TlsKeyFile, constants.ConfigDir+constants.DefaultTLSKeyFile)
	viper.SetDefault(commConfig.TlsCommonName, constants.DefaultIHUBTlsCn)
	viper.SetDefault(commConfig.TlsSanList, constants.DefaultTLSSan)

	//Set default values for log
	viper.SetDefault(commConfig.LogMaxLength, constants.DefaultLogEntryMaxlength)
	viper.SetDefault(commConfig.LogEnableStdout, true)
	viper.SetDefault(commConfig.LogLevel, constants.DefaultLogLevel)
}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASBaseUrl:          viper.GetString(commConfig.AasBaseUrl),
		CMSBaseURL:          viper.GetString(commConfig.CmsBaseUrl),
		CmsTlsCertDigest:    viper.GetString(commConfig.CmsTlsCertSha384),
		PollIntervalMinutes: viper.GetInt(config.PollIntervalMinutes),
		IHUB: commConfig.ServiceConfig{
			Username: viper.GetString(config.IhubServiceUsername),
			Password: viper.GetString(config.IhubServicePassword),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString(commConfig.TlsCertFile),
			KeyFile:    viper.GetString(commConfig.TlsKeyFile),
			CommonName: viper.GetString(commConfig.TlsCommonName),
			SANList:    viper.GetString(commConfig.TlsSanList),
		},
		AttestationService: config.AttestationConfig{
			HVSBaseURL: viper.GetString(config.HvsBaseUrl),
			FDSBaseURL: viper.GetString(config.FdsBaseUrl),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt(commConfig.LogMaxLength),
			Level:        viper.GetString(commConfig.LogLevel),
			EnableStdout: viper.GetBool(commConfig.LogEnableStdout),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		commConfig.TlsSanList: "SAN_LIST",
		commConfig.AasBaseUrl: "AAS_API_URL",
		config.HvsBaseUrl:     "HVS_BASE_URL",
		config.FdsBaseUrl:     "FDS_BASE_URL",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
