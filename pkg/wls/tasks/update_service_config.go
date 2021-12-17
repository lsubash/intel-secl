/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
)

type UpdateServiceConfig struct {
	ServiceConfig commConfig.ServiceConfig
	AASApiUrl     string
	HVSApiUrl     string
	AppConfig     **config.Configuration
	ServerConfig  commConfig.ServerConfig
	DefaultPort   int
	ConsoleWriter io.Writer
}

const envHelpPrompt = "Following environment variables are required for update-service-config setup:"

var envHelp = map[string]string{
	"SERVICE_USERNAME":           "The service username as configured in AAS",
	"SERVICE_PASSWORD":           "The service password as configured in AAS",
	"LOG_LEVEL":                  "Log level",
	"LOG_MAX_LENGTH":             "Max length of log statement",
	"LOG_ENABLE_STDOUT":          "Enable console log",
	"AAS_BASE_URL":               "AAS Base URL",
	"ATTESTATION_TYPE":           "Type of Attestation Service",
	"ATTESTATION_SERVICE_URL":    "Base URL for the Attestation Service",
	"SERVER_PORT":                "The Port on which Server Listens to",
	"SERVER_READ_TIMEOUT":        "Request Read Timeout Duration in Seconds",
	"SERVER_READ_HEADER_TIMEOUT": "Request Read Header Timeout Duration in Seconds",
	"SERVER_WRITE_TIMEOUT":       "Request Write Timeout Duration in Seconds",
	"SERVER_IDLE_TIMEOUT":        "Request Idle Timeout in Seconds",
	"SERVER_MAX_HEADER_BYTES":    "Max Length Of Request Header in Bytes ",
}

func (uc UpdateServiceConfig) Run() error {
	log.Trace("tasks/update_config:Run() Entering")
	defer log.Trace("tasks/update_config:Run() Leaving")
	if uc.ServiceConfig.Username == "" {
		return errors.New("WLS configuration not provided: WLS_SERVICE_USERNAME is not set")
	}
	if uc.ServiceConfig.Password == "" {
		return errors.New("WLS configuration not provided: WLS_SERVICE_PASSWORD is not set")
	}
	if uc.AASApiUrl == "" {
		return errors.New("WLS configuration not provided: AAS_BASE_URL is not set")
	}
	(*uc.AppConfig).AASApiUrl = uc.AASApiUrl
	(*uc.AppConfig).Log = commConfig.LogConfig{
		MaxLength:    viper.GetInt("log-max-length"),
		EnableStdout: viper.GetBool("log-enable-stdout"),
		Level:        viper.GetString("log-level"),
	}

	if uc.ServerConfig.Port < 1024 ||
		uc.ServerConfig.Port > 65535 {
		uc.ServerConfig.Port = uc.DefaultPort
	}
	(*uc.AppConfig).Server = uc.ServerConfig
	(*uc.AppConfig).WLS = uc.ServiceConfig

	fmt.Println("Setting up HVS configuration ...")
	if uc.HVSApiUrl == "" {
		return errors.New("setup/hvs:Run() Missing HVS Endpoint URL in environment")
	}
	log.Info("setup/hvs:Run() Updated HVS endpoint in configuration")

	return nil
}

func (uc UpdateServiceConfig) Validate() error {
	if (*uc.AppConfig).WLS.Username == "" {
		return errors.New("WLS username is not set in the configuration")
	}
	if (*uc.AppConfig).WLS.Password == "" {
		return errors.New("WLS password is not set in the configuration")
	}
	if (*uc.AppConfig).AASApiUrl == "" {
		return errors.New("AAS API url is not set in the configuration")
	}
	if (*uc.AppConfig).Server.Port < 1024 ||
		(*uc.AppConfig).Server.Port > 65535 {
		return errors.New("Configured port is not valid")
	}
	if uc.HVSApiUrl == "" {
		return errors.New("HVS URL is not set")
	}
	return nil
}

func (uc UpdateServiceConfig) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, envHelpPrompt, "", envHelp)
	fmt.Fprintln(w, "")
}

func (uc UpdateServiceConfig) SetName(n, e string) {
}
