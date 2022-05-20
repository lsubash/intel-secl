/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v5/pkg/model/hvs"
)

func Test_ruleBuilderVMWare12_GetAssetTagRules(t *testing.T) {
	type fields struct {
		verifierCertificates VerifierCertificates
		hostManifest         *hvs.HostManifest
		signedFlavor         *hvs.SignedFlavor
		rules                []rules.Rule
	}
	tests := []struct {
		name    string
		fields  fields
		want    []rules.Rule
		wantErr bool
	}{
		{
			name: "Get asset tag rules in vmware",
			fields: fields{
				verifierCertificates: VerifierCertificates{
					AssetTagCACertificates: &x509.CertPool{},
				},
				hostManifest: &hvs.HostManifest{},
				signedFlavor: &hvs.SignedFlavor{
					Flavor: hvs.Flavor{
						External: &hvs.External{},
					},
				},
				rules: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &ruleBuilderVMWare12{
				verifierCertificates: tt.fields.verifierCertificates,
				hostManifest:         tt.fields.hostManifest,
				signedFlavor:         tt.fields.signedFlavor,
				rules:                tt.fields.rules,
			}
			_, err := builder.GetAssetTagRules()
			if (err != nil) != tt.wantErr {
				t.Errorf("ruleBuilderVMWare12.GetAssetTagRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
