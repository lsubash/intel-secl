/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package wlagent

import (
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"os"
	"os/exec"
)

func removeservice() error {
	log.Trace("main:removeservice() Entering")
	defer log.Trace("main:removeservice() Leaving")

	systemctl, err := exec.LookPath(constants.SystemCtlCmd)
	if err != nil {
		return err
	}

	cmd := exec.Command(systemctl, constants.SystemctlDisableOperation, constants.SystemdServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
