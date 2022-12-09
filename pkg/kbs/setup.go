/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"

	cos "github.com/intel-secl/intel-secl/v5/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/utils"

	"github.com/intel-secl/intel-secl/v5/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/tasks"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// input string slice should start with setup
func (app *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, arg := range args {
		if arg == "-f" || arg == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
			} else {
				return errors.New("Invalid answer file name")
			}
		} else if arg == "--force" {
			force = true
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err := setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := app.setupTaskRunner()
	if err != nil {
		return errors.Wrap(err, "Failed to add setup task runner")
	}
	cmd := args[1]
	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == "all" {
			err = runner.PrintAllHelp()
			if err != nil {
				fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
			}
		}
		return nil
	}
	if cmd == "all" {
		if err = runner.RunAll(force); err != nil {
			errCmds := runner.FailedCommands()
			fmt.Fprintln(app.errorWriter(), "Error(s) encountered when running all setup commands:")
			for errCmd, failErr := range errCmds {
				fmt.Fprintln(app.errorWriter(), errCmd+": "+failErr.Error())
				err = runner.PrintHelp(errCmd)
				if err != nil {
					fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
				}
			}
			return errors.New("Failed to run all tasks")
		}
	} else {
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(app.errorWriter(), cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				fmt.Fprintln(app.errorWriter(), "Error(s) encountered when printing help")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}

	err = app.Config.Save(constants.DefaultConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration")
	}
	// Containers are always run as non root users, does not require changing ownership of config directories
	if utils.IsContainerEnv() {
		return nil
	}

	return cos.ChownDirForUser(constants.ServiceUserName, app.configDir())
}

// App helper function for setting up the task runner
func (app *App) setupTaskRunner() (*setup.Runner, error) {
	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
	if app.configuration() == nil {
		app.Config = defaultConfig()
	}

	runner := setup.NewRunner()
	runner.ConsoleWriter = app.consoleWriter()
	runner.ErrorWriter = app.errorWriter()

	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: app.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		TlsCertDigest: viper.GetString(commConfig.CmsTlsCertSha384),
	})
	runner.AddTask("download-cert-tls", "tls", &setup.DownloadCert{
		KeyFile:      app.configDir() + constants.DefaultTLSKeyFile,
		CertFile:     app.configDir() + constants.DefaultTLSCertFile,
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(commConfig.TlsCommonName),
		},
		SanList:       viper.GetString(commConfig.TlsSanList),
		CertType:      "tls",
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: app.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		BearerToken:   viper.GetString(commConfig.BearerToken),
	})
	runner.AddTask("create-default-key-transfer-policy", "", &tasks.CreateDefaultTransferPolicy{
		DefaultTransferPolicyFile: constants.DefaultTransferPolicyFile,
		ConsoleWriter:             app.consoleWriter(),
	})
	runner.AddTask("update-service-config", "", &tasks.UpdateServiceConfig{
		ConsoleWriter: app.consoleWriter(),
		AASBaseUrl:    viper.GetString(commConfig.AasBaseUrl),
		ServiceConfig: commConfig.ServiceConfig{
			Username: viper.GetString(config.KBSServiceUsername),
			Password: viper.GetString(config.KBSServicePassword),
		},
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt(commConfig.ServerPort),
			ReadTimeout:       viper.GetDuration(commConfig.ServerReadTimeout),
			ReadHeaderTimeout: viper.GetDuration(commConfig.ServerReadHeaderTimeout),
			WriteTimeout:      viper.GetDuration(commConfig.ServerWriteTimeout),
			IdleTimeout:       viper.GetDuration(commConfig.ServerIdleTimeout),
			MaxHeaderBytes:    viper.GetInt(commConfig.ServerMaxHeaderBytes),
		},
		DefaultPort: constants.DefaultKBSListenerPort,
		AppConfig:   &app.Config,
	})
	return runner, nil
}
