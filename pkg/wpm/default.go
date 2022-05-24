/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wpm

import (
	"os"

	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/constants"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// set default values for log
	viper.SetDefault(commConfig.LogMaxLength, constants.DefaultLogMaxlength)
	viper.SetDefault(commConfig.LogEnableStdout, false)
	viper.SetDefault(commConfig.LogLevel, constants.DefaultLogLevel)
	viper.SetDefault(config.OciCryptKeyProviderName, constants.OcicryptKeyProviderName)
}

func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		AASApiUrl:               viper.GetString(commConfig.AasBaseUrl),
		CMSBaseURL:              viper.GetString(commConfig.CmsBaseUrl),
		CmsTlsCertDigest:        viper.GetString(commConfig.CmsTlsCertSha384),
		KBSApiUrl:               viper.GetString(config.KbsBaseUrl),
		OcicryptKeyProviderName: viper.GetString(config.OciCryptKeyProviderName),
		WPM: commConfig.ServiceConfig{
			Username: viper.GetString(config.WpmServiceUsername),
			Password: viper.GetString(config.WpmServicePassword),
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
		commConfig.AasBaseUrl: "AAS_API_URL",
		config.KbsBaseUrl:     "KMS_API_URL",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
