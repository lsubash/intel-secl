/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var defaultLog = log.GetDefaultLogger()

// Constants for viper variable names. Will be used to set
// default values as well as to get each value
const (
	ApsBaseUrl  = "aps-base-url"
	CustomToken = "custom-token"

	EndpointUrl = "endpoint-url"
	KeyManager  = "key-manager"

	KmipVersion        = "kmip.version"
	KmipServerIP       = "kmip.server-ip"
	KmipServerPort     = "kmip.server-port"
	KmipHostname       = "kmip.hostname"
	KmipUsername       = "kmip.username"
	KmipPassword       = "kmip.password"
	KmipClientKeyPath  = "kmip.client-key-path"
	KmipClientCertPath = "kmip.client-cert-path"
	KmipRootCertPath   = "kmip.root-cert-path"
)

type Configuration struct {
	AASBaseUrl       string `yaml:"aas-base-url" mapstructure:"aas-base-url"`
	CMSBaseURL       string `yaml:"cms-base-url" mapstructure:"cms-base-url"`
	APSBaseUrl       string `yaml:"aps-base-url" mapstructure:"aps-base-url"`
	CustomToken      string `yaml:"custom-token" mapstructure:"custom-token"`
	CmsTlsCertDigest string `yaml:"cms-tls-cert-sha384" mapstructure:"cms-tls-cert-sha384"`

	EndpointURL string `yaml:"endpoint-url" mapstructure:"endpoint-url"`
	KeyManager  string `yaml:"key-manager" mapstructure:"key-manager"`

	TLS    commConfig.TLSCertConfig `yaml:"tls"`
	Log    commConfig.LogConfig     `yaml:"log"`
	Server commConfig.ServerConfig  `yaml:"server"`

	Kmip KmipConfig `yaml:"kmip"`
}

type KmipConfig struct {
	Version                   string `yaml:"version" mapstructure:"version"`
	ServerIP                  string `yaml:"server-ip" mapstructure:"server-ip"`
	ServerPort                string `yaml:"server-port" mapstructure:"server-port"`
	Hostname                  string `yaml:"hostname" mapstructure:"hostname"`
	Username                  string `yaml:"username" mapstructure:"username"`
	Password                  string `yaml:"password" mapstructure:"password"`
	ClientKeyFilePath         string `yaml:"client-key-path" mapstructure:"client-key-path"`
	ClientCertificateFilePath string `yaml:"client-cert-path" mapstructure:"client-cert-path"`
	RootCertificateFilePath   string `yaml:"root-cert-path" mapstructure:"root-cert-path"`
}

// init sets the configuration file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

// LoadConfiguration loads application specific configuration from config.yml
func LoadConfiguration() (*Configuration, error) {
	ret := Configuration{}
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

// Save saves application specific configuration to config.yml
func (config *Configuration) Save(filename string) error {
	configFile, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing config file")
		}
	}()
	err = yaml.NewEncoder(configFile).Encode(config)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}
