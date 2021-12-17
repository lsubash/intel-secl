/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
)

// Automatically filled in by linker

// Version holds the build revision for the WLS binary
var Version = ""

// GitHash holds the commit hash for the WLS binary
var GitHash = ""

// BuildDate holds the build timestamp for the WLS binary
var BuildDate = ""

func GetVersion() string {
	verStr := fmt.Sprintf("Service Name: %s\n", constants.ExplicitServiceName)
	verStr = verStr + fmt.Sprintf("Version: %s-%s\n", Version, GitHash)
	verStr = verStr + fmt.Sprintf("Build Date: %s\n", BuildDate)
	return verStr
}
