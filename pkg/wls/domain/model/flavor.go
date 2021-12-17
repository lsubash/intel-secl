/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
)

// FlavorFilter defines filter criteria for searching
type FlavorFilter struct {
	FlavorID uuid.UUID `json:"id,omitempty"`
	Label    string    `json:"label,omitempty"`
}

// SignedFlavorCollection is a list of Flavor objects in response to a Flavor Search query
type SignedFlavorCollection struct {
	Flavors []wls.SignedImageFlavor `json:"signed_flavors"`
}
