/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package wlagent

import (
	"fmt"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/setup"
	commSetup "github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"strings"
)

var (
	rpcSocketFilePath = path.Join(constants.RunDirPath, constants.RPCSocketFileName)

	log           = commLog.GetDefaultLogger()
	secLog        = commLog.GetSecurityLogger()
	errInvalidCmd = errors.New("Invalid input after command")
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string

	config *config.Configuration

	ConsoleWriter io.Writer
	ErrorWriter   io.Writer
	LogWriter     io.Writer
	SecLogWriter  io.Writer
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDirPath
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
	viper.AddConfigPath(a.configDir())
	c, err := config.LoadConfiguration()
	if err == nil {
		a.config = c
		return a.config
	}
	return nil
}

func (a *App) configureLogs(stdOut, logFile bool) error {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.logWriter()
	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.secLogWriter())

	logConfig := a.config.Logging
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+logConfig.Level)
	}
	f := commLog.LogFormatter{MaxLength: logConfig.MaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &f, ioWriterSecurity, false)

	secLog.Info(commLogMsg.LogInit)
	log.Info(commLogMsg.LogInit)
	return nil
}

// Run is the primary control loop for wlagent. support setup, start, stop etc
func (a *App) Run(args []string) error {
	log.Trace("main:main() Entering")
	defer log.Trace("main:main() Leaving")

	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Panic occurred: %+v\n%s", err, string(debug.Stack()))
		}
	}()

	if len(os.Args) <= 1 {
		fmt.Fprintf(os.Stderr, "Invalid arguments: %s\n", os.Args)
		a.printUsage()
		os.Exit(1)
	}

	if err := validation.ValidateStrings(os.Args); err != nil {
		secLog.WithError(err).Errorf("%s main:main() Invalid arguments", commLogMsg.InvalidInputBadParam)
		fmt.Fprintln(os.Stderr, "Invalid arguments")
		a.printUsage()
		os.Exit(1)
	}

	switch arg := strings.ToLower(args[1]); arg {
	case "version", "--version", "-v":
		a.printVersion()

	case "setup":
		if err := a.setup(args[1:]); err != nil {
			if errors.Cause(err) == commSetup.ErrTaskNotFound {
				a.printUsageWithError(err)
			} else {
				fmt.Fprintln(a.errorWriter(), err.Error())
			}
			return err
		}

	case "rungrpcservice":
		c := a.configuration()
		if c == nil {
			return errors.New("Failed to load configuration")
		}
		// initialize log
		if err := a.configureLogs(c.Logging.EnableStdout, true); err != nil {
			return err
		}
		a.runGRPCService()

	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.start()

	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.stop()

	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.status()

	case "uninstall":
		_ = a.stop()
		if err := removeservice(); err == nil {
			fmt.Println("Workload Agent Service Removed...")
		}

		deleteFile(constants.WlagentSymLink)
		deleteFile(constants.OptDirPath)
		deleteFile(constants.LogDirPath)
		deleteFile(constants.RunDirPath)
		if len(args) > 2 && strings.ToLower(args[2]) == "--purge" {
			deleteFile(constants.ConfigDirPath)
		}

	default:
		fmt.Printf("Unrecognized option : %s\n", arg)
		secLog.Errorf("%s Command not found", commLogMsg.InvalidInputProtocolViolation)
		fallthrough

	case "help", "-help", "--help":
		a.printUsage()
	}
	return nil
}

func deleteFile(path string) {
	log.Trace("main/main:deleteFile() Entering")
	defer log.Trace("main/main:deleteFile() Leaving")
	fmt.Println("Deleting : ", path)
	// delete file
	var err = os.RemoveAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting file :%s", path)
	}
}

func (a *App) start() error {
	log.Trace("main:start() Entering")
	defer log.Trace("main:start() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start wlagent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, constants.SystemctlStartOperation, constants.SystemdServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) stop() error {
	log.Trace("main:stop() Entering")
	defer log.Trace("main:stop() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop wlagent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, constants.SystemctlStopOperation, constants.SystemdServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) status() error {
	log.Trace("main:status() Entering")
	defer log.Trace("main:status() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status wlagent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, constants.SystemctlStatusOperation, constants.SystemdServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
