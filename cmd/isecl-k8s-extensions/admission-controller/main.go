/*
Copyright © 2021 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package main

import (
	"fmt"
	admission_controller "github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/config"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/router"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/version"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/setup"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"k8s.io/client-go/rest"
	"os"
)

var (
	defaultLog = commLog.GetDefaultLogger()
)

func printVersion() {
	fmt.Fprintf(os.Stdout, version.GetVersion())
}

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

func main() {
	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "version", "--version", "-v":
			printVersion()
		}
	}

	// default to service account in cluster token
	_, err := rest.InClusterConfig()
	if err != nil {
		defaultLog.WithError(err).Error("Failed to read k8s cluster configuration")
		return
	}

	logFile, err := os.OpenFile(constants.DefaultLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open log file err %v", err)
		return
	}

	admissionControllerConfig, err := config.GetAdmissionControllerConfig()
	if err != nil {
		defaultLog.Fatalf("Error while obtaining admission-controller configuration %v", err)
	}

	err = configureLogs(logFile, admissionControllerConfig.LogLevel, admissionControllerConfig.LogMaxLength)
	if err != nil {
		defaultLog.Fatalf("Error while configuring logs %v", err)
	}

	err = admission_controller.StartServer(router.InitRouter(), *admissionControllerConfig)
	if err != nil {
		defaultLog.Error("Error starting server")
		return
	}
	defaultLog.Info("ISecL Admission Controller exit")

}
