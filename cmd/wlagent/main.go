/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/wlagent"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
)

func openLogFiles() (logFile *os.File, secLogFile *os.File, err error) {

	logFile, err = os.OpenFile(constants.DefaultLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, nil, err
	}
	if err = os.Chmod(constants.DefaultLogFilePath, 0640); err != nil {
		return nil, nil, err
	}

	secLogFile, err = os.OpenFile(constants.SecurityLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, nil, err
	}
	if err = os.Chmod(constants.SecurityLogFilePath, 0640); err != nil {
		return nil, nil, err
	}

	return
}

func main() {
	l, s, err := openLogFiles()
	var app *wlagent.App
	if err != nil {
		app = &wlagent.App{
			LogWriter: os.Stdout,
		}
	} else {
		defer func() {
			closeLogFiles(l, s)
		}()
		app = &wlagent.App{
			LogWriter:    l,
			SecLogWriter: s,
		}
	}

	err = app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error:", err.Error())
		os.Exit(1)
	}
}

func closeLogFiles(logFile, secLogFile *os.File) {
	var err error
	err = logFile.Close()
	if err != nil {
		fmt.Println("Failed to close default log file:", err.Error())
	}
	err = secLogFile.Close()
	if err != nil {
		fmt.Println("Failed to close security log file:", err.Error())
	}
}
