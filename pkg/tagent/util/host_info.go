/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"
	"github.com/pkg/errors"
)

func ReadHostInfo(platformInfoFilePath string) (*taModel.HostInfo, error) {
	var hostInfo taModel.HostInfo
	if _, err := os.Stat(platformInfoFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - %s does not exist", message.AppRuntimeErr, constants.PlatformInfoFilePath)
	}

	jsonData, err := ioutil.ReadFile(platformInfoFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - There was an error reading %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
	}

	err = json.Unmarshal(jsonData, &hostInfo)
	if err != nil {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - There was an error unmarshalling the hostInfo", message.AppRuntimeErr)
	}
	return &hostInfo, nil
}
