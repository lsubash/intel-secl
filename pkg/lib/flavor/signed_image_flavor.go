/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
)

/**
 *
 * @author arijitgh
 */

// SignedImageFlavor struct defines the image flavor and
// its corresponding signature
type SignedImageFlavor struct {
	ImageFlavor hvs.Image `json:"flavor"`
	Signature   string    `json:"signature"`
}
