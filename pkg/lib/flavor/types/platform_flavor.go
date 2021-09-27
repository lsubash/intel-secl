/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/model/hvs"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// PlatformFlavor interface must be implemented by specific PlatformFlavor
type PlatformFlavor interface {
	// GetFlavorPartNames retrieves the list of flavor parts that can be obtained using the GetFlavorPartRaw function
	GetFlavorPartNames() ([]hvs.FlavorPartName, error)

	// GetFlavorPartRaw extracts the details of the flavor part requested by the
	// caller from the host report used during the creation of the PlatformFlavor instance
	GetFlavorPartRaw(name hvs.FlavorPartName) ([]hvs.Flavor, error)
}
