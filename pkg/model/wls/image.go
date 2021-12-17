/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	"github.com/google/uuid"
)

type ImageInfo struct {
	ID        string   `json:"id"`
	FlavorIDs []string `json:"flavor_ids"`
}

type ImagesResponse []ImageInfo

type ImageFlavor struct {
	FlavorID uuid.UUID `json:"flavor_id,omitempty"`
	ImageID  uuid.UUID `json:"image_id,omitempty"`
}
