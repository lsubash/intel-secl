/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"

	"github.com/spf13/viper"

	"github.com/pkg/errors"
)

const updateServiceConfigRequiredHelpPrompt = "Following environment variables are required for update-service-config setup:"
const updateServiceConfigOptionalHelpPrompt = "Following environment variables are optional for update-service-config setup:"

var updateServiceConfigRequiredEnvHelp = map[string]string{
	constants.WlaUsernameEnv: "WLA Service Username",
	constants.WlaPasswordEnv: "WLA Service Password",
}

var updateServiceConfigOptionalEnvHelp = map[string]string{
	constants.LogLevelEnvVar:            "Log level",
	constants.LogEntryMaxlengthEnv:      "Maximum length of each entry in a log",
	constants.EnableConsoleLogEnv:       "<true/false> Workload Agent Enable standard output",
	constants.WlsApiUrlEnv:              "Workload Service URL",
	constants.SkipFlavorSignatureVerEnv: "<true/false> Skip flavor signature verification if set to true",
}

type UpdateServiceConfig struct {
	Config                          *config.Configuration
	WlsApiUrl                       string
	WlaAasUser                      string
	WlaAasPassword                  string
	SkipFlavorSignatureVerification bool
	LogConfig                       commConfig.LogConfig
	envPrefix                       string
	commandName                     string
}

func (uc UpdateServiceConfig) Run() error {
	log.Trace("setup/update_service_config:Run() Entering")
	defer log.Trace("setup/update_service_config:Run() Leaving")
	fmt.Println("Running setup task: update_service_config")

	if _, err := url.ParseRequestURI(uc.WlsApiUrl); err != nil {
		uc.Config.Wls.APIUrl = uc.WlsApiUrl
	} else if strings.TrimSpace(uc.Config.Wls.APIUrl) == "" {
		return errors.Wrapf(err, "%s is not defined in environment or configuration file", constants.WlsApiUrlEnv)
	}

	err := validation.ValidateUserNameString(uc.WlaAasUser)
	if err == nil && uc.WlaAasUser != "" {
		uc.Config.Wla.APIUsername = uc.WlaAasUser
	} else if strings.TrimSpace(uc.Config.Wla.APIUsername) == "" {
		return errors.Wrapf(err, "%s is not defined in environment or configuration file", constants.WlaUsernameEnv)
	}

	err = validation.ValidatePasswordString(uc.WlaAasPassword)
	if err == nil && uc.WlaAasPassword != "" {
		uc.Config.Wla.APIPassword = uc.WlaAasPassword
	} else if strings.TrimSpace(uc.Config.Wla.APIPassword) == "" {
		return errors.Wrapf(err, "%s is not defined in environment or configuration file", constants.WlaPasswordEnv)
	}

	uc.Config.Logging = uc.LogConfig

	return nil
}

func (uc UpdateServiceConfig) Validate() error {
	log.Trace("setup/update_service_config:Validate() Entering")
	defer log.Trace("setup/update_service_config:Validate() Leaving")

	log.Info("setup/update_service_config:Validate() Validation for update_service_config")

	if _, err := url.ParseRequestURI(viper.GetString(constants.WlsApiUrlViperKey)); err != nil {
		return errors.Errorf("setup/update_service_config:Validate() " + constants.WlsApiUrlEnv + " is not set")
	}
	if strings.TrimSpace(viper.GetString(constants.WlaUsernameViperKey)) == "" {
		return errors.Errorf("setup/update_service_config:Validate() " + constants.WlaUsernameEnv + " is not set")
	}
	if strings.TrimSpace(viper.GetString(constants.WlaPasswordViperKey)) == "" {
		return errors.Errorf("setup/update_service_config:Validate() " + constants.WlaPasswordEnv + " is not set")
	}
	return nil
}

func (uc UpdateServiceConfig) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, updateServiceConfigRequiredHelpPrompt, "", updateServiceConfigRequiredEnvHelp)
	fmt.Fprintln(w, "")
	setup.PrintEnvHelp(w, updateServiceConfigOptionalHelpPrompt, "", updateServiceConfigOptionalEnvHelp)
	fmt.Fprintln(w, "")
}

func (uc UpdateServiceConfig) SetName(n, e string) {
	uc.commandName = n
	uc.envPrefix = setup.PrefixUnderscroll(e)
}
