/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
)

type hostTrustCache struct {
	hostID         uuid.UUID
	trustedFlavors map[uuid.UUID]*hvs.Flavor
	// TODO: consider using a map here rather than traversing through the list when we need to remove flavors
	trustReport hvs.TrustReport
}

// TODO:
// These functions should have been implemented in
// "github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
// for the structure hvs.FlavorCollection
func (htc *hostTrustCache) addTrustedFlavors(f *hvs.Flavor) {
	if htc.trustedFlavors == nil {
		htc.trustedFlavors = map[uuid.UUID]*hvs.Flavor{}
	}
	if f != nil && f.Meta.ID != uuid.Nil {
		htc.trustedFlavors[f.Meta.ID] = f
	}
}

func (htc *hostTrustCache) removeTrustedFlavors(fIn *hvs.Flavor) {
	if fIn == nil {
		return
	}
	delete(htc.trustedFlavors, fIn.Meta.ID)
}

func (htc *hostTrustCache) isTrustCacheEmpty() bool {
	return len(htc.trustedFlavors) == 0
}
