/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package verifier

import (
	"github.com/intel-secl/intel-secl/v4/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
)

type vendorTrustPolicyReader interface {
	Rules() []rules.Rule
}

type hostTrustPolicyManager struct {
}

func NewHostTrustPolicyManager(hvs.Flavor, *hvs.HostManifest) *hostTrustPolicyManager {
	return &hostTrustPolicyManager{}
}

func (htpm *hostTrustPolicyManager) GetVendorTrustPolicyReader() vendorTrustPolicyReader {
	return nil
}
