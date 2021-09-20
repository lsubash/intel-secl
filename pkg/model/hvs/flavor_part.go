/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"strings"

	commLog "github.com/intel-secl/intel-secl/v4/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// FlavorPart
type FlavorPartName string

const (
	FlavorPartPlatform   FlavorPartName = "PLATFORM"
	FlavorPartOs         FlavorPartName = "OS"
	FlavorPartHostUnique FlavorPartName = "HOST_UNIQUE"
	FlavorPartSoftware   FlavorPartName = "SOFTWARE"
	FlavorPartAssetTag   FlavorPartName = "ASSET_TAG"
)

// GetFlavorTypes returns a list of flavor types
func GetFlavorTypes() []FlavorPartName {
	log.Trace("flavor/common/flavor_part:GetFlavorTypes() Entering")
	defer log.Trace("flavor/common/flavor_part:GetFlavorTypes() Leaving")

	return []FlavorPartName{FlavorPartPlatform, FlavorPartOs, FlavorPartHostUnique, FlavorPartSoftware, FlavorPartAssetTag}
}

// GetFlavorTypesString returns a list of flavor types as strings for given flavor types
func GetFlavorTypesString(flavorParts []FlavorPartName) []string {
	log.Trace("flavor/common/flavor_part:GetFlavorTypesString() Entering")
	defer log.Trace("flavor/common/flavor_part:GetFlavorTypesString() Leaving")
	var flavorTypes []string
	for _, flavorPart := range flavorParts {
		flavorTypes = append(flavorTypes, flavorPart.String())
	}
	return flavorTypes
}

func (fp FlavorPartName) String() string {
	return string(fp)
}

// Parse Converts a string to a FlavorPart.  If the string does
// not match a supported FlavorPart, an error is returned and the
// FlavorPart value 'UNKNOWN'.
func (flavorPart *FlavorPartName) Parse(flavorPartString string) error {

	var result FlavorPartName
	var err error

	switch strings.ToUpper(flavorPartString) {
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

// Filter Unique flavor parts from input slice of flavor parts
func FilterUniqueFlavorParts(flavorParts []FlavorPartName) []FlavorPartName {
	if flavorParts != nil && len(flavorParts) > 0 {
		flavorPartMap := make(map[string]bool)
		filteredParts := []FlavorPartName{}
		for _, entry := range flavorParts {
			flavorPart := entry.String()
			if _, value := flavorPartMap[flavorPart]; !value {
				flavorPartMap[flavorPart] = true
				filteredParts = append(filteredParts, entry)
			}
		}
		return filteredParts
	}
	return nil
}
