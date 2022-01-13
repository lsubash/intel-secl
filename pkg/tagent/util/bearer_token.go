/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"os"
	"strings"

	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"
)

func GetBearerToken() string {
	return strings.TrimSpace(os.Getenv(constants.EnvBearerToken))
}
