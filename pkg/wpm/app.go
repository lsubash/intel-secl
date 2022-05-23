/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wpm

import (
	"fmt"
	"io"
	"os"

	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/constants"
	ocicrypt_keyprovider "github.com/intel-secl/intel-secl/v5/pkg/wpm/ocicrypt-keyprovider"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var errInvalidCmd = errors.New("Invalid input after command")
var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	ErrorWriter    io.Writer
	LogWriter      io.Writer
	SecLogWriter   io.Writer
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}
func (a *App) errorWriter() io.Writer {
	if a.ErrorWriter != nil {
		return a.ErrorWriter
	}
	return os.Stderr
}

func (a *App) secLogWriter() io.Writer {
	if a.SecLogWriter != nil {
		return a.SecLogWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	c, err := config.LoadConfiguration()
	if err == nil {
		a.Config = c
		return a.Config
	}
	return nil
}

func (a *App) configureLogs(isStdOut, isFileOut bool) error {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.LogWriter
	if isStdOut {
		if isFileOut {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}

	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.secLogWriter())
	logConfig := a.Config.Log
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+logConfig.Level)
	}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &commLog.LogFormatter{MaxLength: logConfig.MaxLength}, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &commLog.LogFormatter{MaxLength: logConfig.MaxLength}, ioWriterSecurity, false)

	secLog.Info(message.LogInit)
	log.Info(message.LogInit)
	return nil
}

func (a *App) Run(args []string) error {

	if len(args) < 2 {
		a.printUsage()
		return nil
	}
	cmd := args[1]
	switch cmd {
	default:
		err := errors.New("Invalid command: " + cmd)
		a.printUsageWithError(err)
		return err
	case "help", "-h", "--help":
		a.printUsage()
		return nil
	case "uninstall":
		// the only allowed flag is --purge
		purge := false
		if len(args) == 3 {
			if args[2] != "--purge" {
				return errors.New("Invalid flag: " + args[2])
			}
			purge = true
		} else if len(args) != 2 {
			return errInvalidCmd
		}
		return a.uninstall(purge)
	case "version", "--version", "-v":
		a.printVersion()
		return nil
	case "setup":
		if err := a.setup(args[1:]); err != nil {
			if errors.Cause(err) == setup.ErrTaskNotFound {
				a.printUsageWithError(err)
			} else {
				fmt.Fprintln(a.errorWriter(), err.Error())
			}
			return err
		}
	case "get-ocicrypt-wrappedkey":
		configuration := a.configuration()
		if err := a.configureLogs(configuration.Log.EnableStdout, true); err != nil {
			return err
		}
		kbsClient, err := util.NewKBSClient(configuration, constants.TrustedCaCertsDir)
		if err != nil {
			return err
		}
		keyProvider := ocicrypt_keyprovider.NewKeyProvider(os.Stdin, configuration.OcicryptKeyProviderName,
			configuration.KBSApiUrl, constants.EnvelopePublickeyLocation, constants.EnvelopePrivatekeyLocation, kbsClient)
		return keyProvider.GetKey()
	}
	return nil
}
