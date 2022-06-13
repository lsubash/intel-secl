/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	taModel "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/util"
	"github.com/pkg/errors"
)

// GetHostInfo Assuming that the /opt/trustagent/var/system-info/platform-info file has been created
// during startup, this function reads the contents of the json file and returns the corresponding
// HostInfo structure.
func (handler *requestHandlerImpl) GetHostInfo(platformInfoFilePath string) (*taModel.HostInfo, error) {
	var hostInfo *taModel.HostInfo

	hostInfo, err := util.ReadHostInfo(platformInfoFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading host-info file %s", platformInfoFilePath)
	}

	return hostInfo, nil
}
