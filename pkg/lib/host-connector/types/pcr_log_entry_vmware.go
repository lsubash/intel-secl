/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package types

import "github.com/intel-secl/intel-secl/v5/pkg/model/hvs"

type EventDetails struct {
	DataHash           []int
	DataHashMethod     hvs.SHAAlgorithm
	ComponentName      *string
	VibName            *string
	VibVersion         *string
	VibVendor          *string
	CommandLine        *string
	OptionsFileName    *string
	BootOptions        *string
	BootSecurityOption *string
}

type TpmEvent struct {
	PcrIndex     int
	EventDetails EventDetails
}
