/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

func newPcrEventLogIntegrity(expectedPcr *types.Pcr, marker common.FlavorPart) (rule, error) {
	if expectedPcr == nil {
		return nil, errors.New("The expected pcr cannot be nil")
	}

	rule := pcrEventLogIntegrity{
		expectedPcr: expectedPcr,
		marker: marker,
	}
	return &rule, nil
}

type pcrEventLogIntegrity struct {
	expectedPcr *types.Pcr
	marker      common.FlavorPart
}

// - If the hostmanifest's PcrManifest is not present, create PcrManifestMissing fault.
// - If the hostmanifest does not contain a pcr at 'expected' bank/index, create a PcrValueMissing fault.
// - If the hostmanifest does not have an event log at 'expected' bank/index, create a 
//   PcrEventLogMissing fault.
// - Otherwise, replay the hostmanifest's event log at 'expected' bank/index and verify the 
//   the cumulative hash matches the 'expected' pcr's 'value'.  If not, crete a PcrEventLogInvalid fault.
func (rule *pcrEventLogIntegrity) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	result := RuleResult{}
	result.Trusted = true
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogIntegrity"
	result.Rule.ExpectedPcr = rule.expectedPcr
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
		} else {
			actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
			if err != nil {
				return nil, err
			}
		
			if actualEventLog == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(rule.expectedPcr.Index))
			} else {
				calculatedValue, err := actualEventLog.Replay()
				if err != nil {
					return nil, err
				}

				if calculatedValue != rule.expectedPcr.Value {
					fault := Fault{
						Name:        FaultPcrEventLogInvalid,
						Description: fmt.Sprintf("PCR %d Event Log is invalid", rule.expectedPcr.Index),
						PcrIndex: &rule.expectedPcr.Index,
					}

					result.Faults = append(result.Faults, fault)
				}
			}
		}
	}

	return &result, nil
}