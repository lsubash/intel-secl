/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// this function sets the configure file name and type
func init() {
	viper.SetConfigName(constants.ConfigFileName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(constants.ConfigDirPath)
}

type HvsConfig struct {
	APIUrl string `yaml:"api-url" mapstructure:"api-url"`
}

type WlsConfig struct {
	APIUrl string `yaml:"api-url" mapstructure:"api-url"`
}

type WlaConfig struct {
	APIUsername string `yaml:"api-user-name" mapstructure:"api-user-name"`
	APIPassword string `yaml:"api-password" mapstructure:"api-password"`
}

type TaConfig struct {
	ConfigDir  string `yaml:"config-dir" mapstructure:"config-dir"`
	AikPemFile string `yaml:"aik-pem-file" mapstructure:"aik-pem-file"`
	User       string `yaml:"user" mapstructure:"user"`
}

type AasConfig struct {
	BaseURL string `yaml:"base-url" mapstructure:"base-url"`
}

type CmsConfig struct {
	BaseURL          string `yaml:"base-url" mapstructure:"base-url"`
	CmsTlsCertDigest string `yaml:"tls-cert-sha384" mapstructure:"tls-cert-sha384"`
}

// Configuration is the global configuration struct that is marshalled/unmarshalled to a persisted yaml file
type Configuration struct {
	BindingKeySecret                string               `yaml:"binding-key-secret" mapstructure:"binding-key-secret"`
	SigningKeySecret                string               `yaml:"signing-key-secret" mapstructure:"signing-key-secret"`
	Hvs                             HvsConfig            `yaml:"hvs" mapstructure:"hvs"`
	Wls                             WlsConfig            `yaml:"wls" mapstructure:"wls"`
	Wla                             WlaConfig            `yaml:"wla" mapstructure:"wla"`
	TrustAgent                      TaConfig             `yaml:"trustagent" mapstructure:"trustagent"`
	Aas                             AasConfig            `yaml:"aas" mapstructure:"aas"`
	Cms                             CmsConfig            `yaml:"cms" mapstructure:"cms"`
	SkipFlavorSignatureVerification bool                 `yaml:"skip-flavor-signature-verification" mapstructure:"skip-flavor-signature-verification"`
	Logging                         commConfig.LogConfig `yaml:"log" mapstructure:"log"`
}

var (
	secLog = commLog.GetSecurityLogger()
	log    = commLog.GetDefaultLogger()
)

func getFileContentFromConfigDir(fileName string) ([]byte, error) {
	filePath := path.Join(constants.ConfigDirPath, fileName)
	// check if key file exists
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("File does not exist - %s", filePath)
	}

	return ioutil.ReadFile(filePath)
}

func GetSigningKeyFromFile() ([]byte, error) {
	log.Trace("config/config:GetSigningKeyFromFile() Entering")
	defer log.Trace("config/config:GetSigningKeyFromFile() Leaving")

	return getFileContentFromConfigDir(constants.SigningKeyFileName)
}

func GetBindingKeyFromFile() ([]byte, error) {
	log.Trace("config/config:GetBindingKeyFromFile() Entering")
	defer log.Trace("config/config:GetBindingKeyFromFile() Leaving")

	return getFileContentFromConfigDir(constants.BindingKeyFileName)
}

func LoadConfiguration() (*Configuration, error) {
	var ret Configuration
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}
	if err := viper.Unmarshal(&ret); err != nil {
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}

func (cfg *Configuration) Save(filename string) error {
	configFile, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing config file")
		}
	}()
	err = yaml.NewEncoder(configFile).Encode(cfg)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}

	if err := os.Chmod(filename, 0640); err != nil {
		return errors.Wrap(err, "Failed to apply permissions to config file")
	}
	return nil
}
