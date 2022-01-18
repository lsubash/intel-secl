/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wlagent

import (
	"os"
	"path/filepath"

	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"

	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/spf13/viper"
)

// init sets the default values for viper keys
func init() {
	loadAlias()
	// for logging params
	viper.SetDefault(constants.LogMaxLengthViperKey, constants.DefaultLogEntryMaxlength)
	viper.SetDefault(constants.LogStdoutViperKey, false)
	viper.SetDefault(constants.LogLevelViperKey, constants.DefaultLogLevel)

	// for TA params
	viper.SetDefault(constants.TaConfigDirViperKey, constants.DefaultTrustagentConfigPath)
	viper.SetDefault(constants.TaAikPemFileViperKey, filepath.Join(constants.DefaultTrustagentConfigPath, constants.TAAikPemFileName))
	viper.SetDefault(constants.TaUserViperKey, constants.DefaultTrustagentUser)

	viper.SetDefault(constants.SkipFlavorSignatureVerificationViperKey, false)

}

// defaultConfig sets up the initializes configuration with defaults
func defaultConfig() *config.Configuration {
	loadAlias()
	return &config.Configuration{
		Aas: config.AasConfig{BaseURL: viper.GetString(constants.AasBaseUrlViperKey)},
		Cms: config.CmsConfig{
			BaseURL:          viper.GetString(constants.CmsBaseUrlViperKey),
			CmsTlsCertDigest: viper.GetString(constants.CmsTlsCertDigestViperKey),
		},
		Logging: commConfig.LogConfig{
			MaxLength:    viper.GetInt(constants.LogMaxLengthViperKey),
			EnableStdout: viper.GetBool(constants.LogStdoutViperKey),
			Level:        viper.GetString(constants.LogLevelViperKey),
		},
		Hvs: config.HvsConfig{
			APIUrl: viper.GetString(constants.HvsApiUrlViperKey),
		},
		TrustAgent: config.TaConfig{
			ConfigDir:  viper.GetString(constants.TaConfigDirViperKey),
			AikPemFile: viper.GetString(constants.TaAikPemFileViperKey),
			User:       viper.GetString(constants.TaUserViperKey),
		},
		Wla: config.WlaConfig{
			APIUsername: viper.GetString(constants.WlaUsernameViperKey),
			APIPassword: viper.GetString(constants.WlaPasswordViperKey),
		},
		Wls:              config.WlsConfig{APIUrl: viper.GetString(constants.WlsApiUrlViperKey)},
		BindingKeySecret: viper.GetString(constants.BindingKeySecretViperKey),
		SigningKeySecret: viper.GetString(constants.SigningKeySecretViperKey),
	}
}

// loadAlias sets up alternative legacy keys for settings
func loadAlias() {
	alias := map[string]string{
		constants.AasBaseUrlViperKey:       constants.AasUrlEnv,
		constants.LogStdoutViperKey:        constants.EnableConsoleLogEnv,
		constants.HvsApiUrlViperKey:        constants.HvsUrlEnv,
		constants.LogMaxLengthViperKey:     constants.LogEntryMaxlengthEnv,
		constants.CmsTlsCertDigestViperKey: constants.CmsTlsCertSha384Env,
		constants.WlaUsernameViperKey:      constants.WlaUsernameEnv,
		constants.WlaPasswordViperKey:      constants.WlaPasswordEnv,
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
