/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package workload

import (
	"errors"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/pkg/instance"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
)

// IntegrityMatches is a rule that enforces container integrity policy
type IntegrityMatches struct {
	RuleName          string            `json:"rule_name"`
	Markers           []string          `json:"markers"`
	IntegrityEnforced ExpectedIntegrity `json:"expected"`
}

// ExpectedIntegrity is a data template that defines the json tag name of the integrity requirement, and the expected boolean value
type ExpectedIntegrity struct {
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

const IntegrityMatchesName = "IntegrityMatches"

func newIntegrityMatches(imageType string, integrityEnforced bool) *IntegrityMatches {
	return &IntegrityMatches{
		IntegrityMatchesName,
		[]string{imageType},
		ExpectedIntegrity{
			"integrity_enforced",
			integrityEnforced,
		},
	}
}

// Name returns the name of the IntegrityMatches Rule.
func (em *IntegrityMatches) Name() string {
	return em.RuleName
}

// apply returns a true if the rule application concludes the manifest is trusted
// if it returns false, a list of Fault's are supplied explaining why.
func (em *IntegrityMatches) Apply(manifest interface{}) (bool, []wls.Fault) {
	// assert manifest as InstanceManifest
	if manifest, ok := manifest.(*instance.Manifest); ok {
		// if rule expects integrity_enforced to be true
		if em.IntegrityEnforced.Value {
			// then instanceManifest image must be encrypted
			if manifest.ImageIntegrityEnforced {
				return true, nil
			}
			return false, []wls.Fault{{Description: "integrity_enforced is \"true\" but Manifest.ImageIntegrityEnforced is \"false\"", Cause: nil}}
		} else {
			if !manifest.ImageIntegrityEnforced {
				return true, nil
			}
			return false, []wls.Fault{{Description: "integrity_enforced is \"false\" but Manifest.ImageIntegrityEnforced is \"true\"", Cause: nil}}
		}
	}
	return false, []wls.Fault{{Description: "invalid manifest type for rule", Cause: errors.New("failed to type assert manifest")}}
}
