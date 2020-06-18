/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"strings"
	"github.com/pkg/errors"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// FlavorPart
type FlavorPart string

const (
	FlavorPartPlatform   FlavorPart = "PLATFORM"
	FlavorPartOs         FlavorPart = "OS"
	FlavorPartHostUnique FlavorPart = "HOST_UNIQUE"
	FlavorPartSoftware   FlavorPart = "SOFTWARE"
	FlavorPartAssetTag   FlavorPart = "ASSET_TAG"
)

// GetFlavorTypes returns a list of flavor types as strings
func GetFlavorTypes() []FlavorPart {
	log.Trace("flavor/common/flavor_part:GetFlavorTypes() Entering")
	defer log.Trace("flavor/common/flavor_part:GetFlavorTypes() Leaving")

	return []FlavorPart{FlavorPartPlatform, FlavorPartOs, FlavorPartHostUnique, FlavorPartSoftware, FlavorPartAssetTag}
}

func (fp FlavorPart) String() string {
	log.Trace("flavor/common/flavor_part/FlavorPart:String() Entering")
	defer log.Trace("flavor/common/flavor_part/FlavorPart:String() Leaving")

	return string(fp)
}

// Parse Converts a string to a FlavorPart.  If the string does
// not match a supported FlavorPart, an error is returned and the
// FlavorPart value 'UNKNOWN'.
func (flavorPart *FlavorPart) Parse(flavorPartString string) error {

	var result FlavorPart
	var err error
	
	switch(strings.ToUpper(flavorPartString)) {
	case string(FlavorPartPlatform):
		result = FlavorPartPlatform
	case string(FlavorPartOs):
		result = FlavorPartOs
	case string(FlavorPartHostUnique):
		result = FlavorPartHostUnique
	case string(FlavorPartSoftware):
		result = FlavorPartSoftware
	case string(FlavorPartAssetTag):
		result = FlavorPartAssetTag
	default:
		err = errors.Errorf("Invalid flavor part string '%s'", flavorPartString)
	}

	*flavorPart = result
	return err
}
