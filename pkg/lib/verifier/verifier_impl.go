/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Implements 'Verifier' interface.
//

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/pkg/errors"
)

type verifierImpl struct {
	signedFlavor         *hvs.SignedFlavor
	verifierCertificates VerifierCertificates
	overallTrust         bool
}

func (v *verifierImpl) Verify(hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor, skipSignedFlavorVerification bool) (*hvs.TrustReport, error) {

	var err error

	if hostManifest == nil {
		return nil, errors.New("The host manifest cannot be nil")
	}

	if signedFlavor == nil {
		return nil, errors.New("The signed flavor cannot be nil")
	}

	v.signedFlavor = signedFlavor

	// default overall trust to true, change to falsed during rule evaluation
	v.overallTrust = true

	ruleFactory := newRuleFactory(v.verifierCertificates, hostManifest, v.signedFlavor, skipSignedFlavorVerification)
	rules, policyName, err := ruleFactory.getVerificationRules()
	if err != nil {
		return nil, err
	}

	results, err := v.applyRules(rules, hostManifest)
	if err != nil {
		return nil, err
	}

	trustReport := hvs.TrustReport{
		PolicyName: policyName,
		Results:    results,
		Trusted:    v.overallTrust,
	}

	return &trustReport, nil
}


func (v *verifierImpl) applyRules(rulesToApply []rules.Rule, hostManifest *types.HostManifest) ([]hvs.RuleResult, error) {

	var results []hvs.RuleResult

	for _, rule := range rulesToApply {

		log.Debugf("Applying verifier rule %T", rule)
		result, err := rule.Apply(hostManifest)
		if err != nil {
			return nil, errors.Wrapf(err, "Error ocrurred applying rule type '%T'", rule)
		}

		// if 'Apply' returned a result with any faults, then the 
		// rule is not trusted
		if len(result.Faults) > 0 {
			result.Trusted = false
			v.overallTrust = false
		}

		// assign the flavor id to all rules
		result.FlavorId = v.signedFlavor.Flavor.Meta.ID

		results = append(results, *result)
	}

	return results, nil
}
