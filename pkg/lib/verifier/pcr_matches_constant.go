/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Rule that compares the 'expected' PCR with the value stored in the host manifest.
//

import (
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

func newPcrMatchesConstant(expectedPcr *types.Pcr, marker common.FlavorPart) (rule, error) {
	if expectedPcr == nil {
		return nil, errors.New("The expected PCR cannot be nil")
	}

	if len(expectedPcr.Value) == 0 {
		return nil, errors.New("The expected PCR cannot have an empty value")
	}

	rule := pcrMatchesConstant{
		expectedPcr: *expectedPcr,
		marker: marker,
	}
	return &rule, nil
}

type pcrMatchesConstant struct {
	expectedPcr types.Pcr
	marker      common.FlavorPart
}

func (rule *pcrMatchesConstant) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	result := RuleResult{}
	result.Trusted = true // default to true, set to false in fault logic
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.PcrMatchesConstant"
	result.Rule.ExpectedPcr = &rule.expectedPcr
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {

		actualPcr, err := hostManifest.PcrManifest.GetPcrValue(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
		if err != nil {
			return nil, err
		}

		if actualPcr == nil {
			result.Faults = append(result.Faults, newPcrValueMissingFault(rule.expectedPcr.PcrBank, rule.expectedPcr.Index))
		} else if rule.expectedPcr.Value != actualPcr.Value {
			result.Faults = append(result.Faults, newPcrValueMismatchFault(rule.expectedPcr.Index, rule.expectedPcr, *actualPcr))
		}
	}

	return &result, nil
}
