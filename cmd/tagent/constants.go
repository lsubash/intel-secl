/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

const (
	ServiceUserName = "trustagent"
	ServiceDir      = "trustagent/"
	LogDir          = "/home/root/tep_luks_dev/log/" + ServiceDir
	LogFile         = LogDir + ServiceUserName + ".log"
	HttpLogFile     = LogDir + ServiceUserName + "-http.log"
	SecurityLogFile = LogDir + ServiceUserName + "-security.log"
	TagentUserName  = "root"
)
