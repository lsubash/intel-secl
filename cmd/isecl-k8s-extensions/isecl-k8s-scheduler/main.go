/*
Copyright © 2021 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package main

import (
	"fmt"
	isecl_k8s_scheduler "github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/config"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/router"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/version"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/setup"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"os"
)

var defaultLog = commLog.GetDefaultLogger()

func configureLogs(logFile *os.File, loglevel string, maxLength int) error {

	lv, err := logrus.ParseLevel(loglevel)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+loglevel)
	}

	ioWriterDefault := io.MultiWriter(os.Stdout, logFile)
	f := commLog.LogFormatter{MaxLength: maxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)

	defaultLog.Info(commLogMsg.LogInit)
	return nil
}

func printVersion() {
	fmt.Fprintf(os.Stdout, version.GetVersion())
}

func main() {

	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "version", "--version", "-v":
			printVersion()
		}
	}

	var err error

	logFile, err := os.OpenFile(constants.LogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, constants.FilePerms)
	if err != nil {
		fmt.Println("Unable to open log file")
		return
	}

	// fetch all the cmd line args
	extendedSchedConfig, err := config.GetExtendedSchedulerConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting parsing variables %v\n", err.Error())
		return
	}

	err = configureLogs(logFile, extendedSchedConfig.LogLevel, extendedSchedConfig.LogMaxLength)
	if err != nil {
		defaultLog.Fatalf("Error while configuring logs %v", err)
	}

	schedRouter := router.InitRoutes(extendedSchedConfig.IntegrationHubPublicKeys, extendedSchedConfig.TagPrefix)

	err = isecl_k8s_scheduler.StartServer(schedRouter, *extendedSchedConfig)
	if err != nil {
		defaultLog.Error("Error starting server")
	}
	defaultLog.Info("ISecL Extended Scheduler Server exit")
}
