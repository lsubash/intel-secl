/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package workload

import (
	"encoding/json"
	"fmt"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
)

// Result is a struct that indicates the evaluation conclusion of applying a rule against a manifest.
// The FlavorID from which the rule derived from is included as well.
type Result struct {
	// Rule is an interface, and can be any concrete interface. You will need to apply a type assertion based on what it is if you need to access it's fields.
	Rule     Rule        `json:"rule"`
	FlavorID string      `json:"flavor_id"`
	Faults   []wls.Fault `json:"faults,omitempty"`
	Trusted  bool        `json:"trusted"`
}

// UnmarshalJSON makes Result Implement the JSON unmarshalling interface
func (r *Result) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var rawRule map[string]json.RawMessage
	if err := json.Unmarshal(raw["rule"], &rawRule); err != nil {
		return err
	}
	var ruleName string
	if err := json.Unmarshal(rawRule["rule_name"], &ruleName); err != nil {
		return err
	}
	switch ruleName {
	case EncryptionMatchesName:
		var ie wls.EncryptionMatches
		if err := json.Unmarshal(raw["rule"], &ie); err != nil {
			return err
		}
		r.Rule = &ie
	case IntegrityMatchesName:
		var ie IntegrityMatches
		if err := json.Unmarshal(raw["rule"], &ie); err != nil {
			return err
		}
		r.Rule = &ie
	case FlavorIntegrityMatchesName:
		var ie FlavorIntegrityMatches
		if err := json.Unmarshal(raw["rule"], &ie); err != nil {
			return err
		}
		r.Rule = &ie
	default:
		return fmt.Errorf("json: cannot unmarshal rule with unrecognized name %s", ruleName)
	}

	// unmarshal everything else
	if err := json.Unmarshal(raw["flavor_id"], &r.FlavorID); err != nil {
		return err
	}
	// faults is optional
	if _, ok := raw["faults"]; ok {
		err := json.Unmarshal(raw["faults"], &r.Faults)
		if err != nil {
			return err
		}
	}
	if err := json.Unmarshal(raw["trusted"], &r.Trusted); err != nil {
		return err
	}
	return nil
}

// Rule defines a trust rule to apply to a manifest.
type Rule interface {
	Name() string
	Apply(actual interface{}) (bool, []wls.Fault)
}
