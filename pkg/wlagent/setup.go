/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wlagent

import (
	"fmt"
	"os"
	"strings"

	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	commSetup "github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/tpmprovider"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/tasks"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// input string slice should start with setup
func (a *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, s := range args {
		if s == "-f" || s == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
			} else {
				return errors.New("Invalid answer file name")
			}
		} else if s == "--force" {
			force = true
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err := commSetup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := a.setupTaskRunner()
	if err != nil {
		return err
	}
	cmd := args[1]
	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == constants.SetupAllCommand {
			err = runner.PrintAllHelp()
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		}
		return nil
	}
	if cmd == constants.SetupAllCommand {
		if err = runner.RunAll(force); err != nil {
			errCmds := runner.FailedCommands()
			fmt.Fprintln(a.errorWriter(), "Error(s) encountered when running all setup commands:")
			for errCmd, failErr := range errCmds {
				fmt.Fprintln(a.errorWriter(), errCmd+": "+failErr.Error())
				err = runner.PrintHelp(errCmd)
				if err != nil {
					return errors.Wrap(err, "Failed to write to console")
				}
			}
			return errors.New("Failed to run all tasks")
		}
		fmt.Fprintln(a.consoleWriter(), "All setup tasks succeeded")
	} else {
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(a.errorWriter(), cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}

	err = a.config.Save(constants.DefaultConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration")
	}
	// WLA always run as root users, does not require changing ownership of config directories
	return nil
}

// a helper function for setting up the task runner
func (a *App) setupTaskRunner() (*commSetup.Runner, error) {

	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer(
		constants.ViperKeyDashSeparator, constants.EnvNameSeparator,
		constants.ViperDotSeparator, constants.EnvNameSeparator))
	viper.AutomaticEnv()

	if a.config == nil {
		a.config = defaultConfig()
	}

	tpmFactory, err := tpmprovider.LinuxTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		fmt.Println("Error while creating the tpm factory.")
		os.Exit(1)
	}

	runner := commSetup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	runner.AddTask(constants.DownloadRootCACertCommand, "", &commSetup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(constants.CmsBaseUrlViperKey),
		TlsCertDigest: viper.GetString(constants.CmsTlsCertDigestViperKey),
	})
	runner.AddTask(constants.CreateSigningKey, "", &tasks.SigningKey{
		Config: a.config,
		T:      tpmFactory,
	})
	runner.AddTask(constants.CreateBindingKey, "", &tasks.BindingKey{
		Config: a.config,
		T:      tpmFactory,
	})
	runner.AddTask(constants.RegisterBindingKeyCommand, "", &tasks.RegisterBindingKey{
		Config:     a.config,
		HvsUrl:     viper.GetString(constants.HvsApiUrlViperKey),
		TaUserName: viper.GetString(constants.TaUserViperKey),
	})
	runner.AddTask(constants.RegisterSigningKeyCommand, "", &tasks.RegisterSigningKey{
		Config: a.config,
		HvsUrl: viper.GetString(constants.HvsApiUrlViperKey),
	})

	runner.AddTask(constants.UpdateServiceConfigCommand, "", &tasks.UpdateServiceConfig{
		Config:                          a.config,
		WlsApiUrl:                       viper.GetString(constants.WlsApiUrlViperKey),
		WlaAasUser:                      viper.GetString(constants.WlaUsernameViperKey),
		WlaAasPassword:                  viper.GetString(constants.WlaPasswordViperKey),
		SkipFlavorSignatureVerification: viper.GetBool(constants.SkipFlavorSignatureVerificationViperKey),
		LogConfig: commConfig.LogConfig{
			MaxLength:    viper.GetInt(constants.LogMaxLengthViperKey),
			EnableStdout: viper.GetBool(constants.LogStdoutViperKey),
			Level:        viper.GetString(constants.LogLevelViperKey),
		},
	})

	return runner, nil
}
