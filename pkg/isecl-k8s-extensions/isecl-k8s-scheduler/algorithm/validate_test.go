/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package algorithm

import (
	"fmt"
	"testing"
	"time"

	"github.com/Waterdrips/jwt-go"
	v1 "k8s.io/api/core/v1"
)

func TestValidatePodWithHvsAnnotation(t *testing.T) {

	claimtest1 := map[string]interface{}{"assetTags": "test_data", "assettagnode": "test_data"}
	claimtest2 := map[string]interface{}{"hardwareFeatures": "test_data", "hwnode": "test_data"}
	claimtest3 := map[string]interface{}{"trustTag": "test_data"}

	type args struct {
		nodeData    []v1.NodeSelectorRequirement
		claims      jwt.MapClaims
		trustprefix string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test 1 meExistInClaims is false",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      ".isecl",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims:      jwt.MapClaims{},
				trustprefix: ".isecl",
			},
			want: true,
		},
		{
			name: "Test 2 case trustTagPresent",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      "test-isecl",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims: jwt.MapClaims{
					"test-isecl": true,
				},
				trustprefix: ".isecl",
			},
			want: false,
		},
		{
			name: "Test 3 case hardwareFeatureClaimsPresent",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      ".iseclhwnode",
						Operator: "In",
						Values:   []string{"test_data"},
					},
				},
				claims: jwt.MapClaims{
					"hardwareFeatures": claimtest2,
				},
				trustprefix: ".isecl",
			},
			want: false,
		},
		{
			name: "Test 4 case assettag",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      ".iseclassettagnode",
						Operator: "In",
						Values:   []string{"test_data"},
					},
				},
				claims: jwt.MapClaims{
					"assetTags": claimtest1,
				},
				trustprefix: ".isecl",
			},
			want: false,
		},
		{
			name: "Test 5 case trustTagClaim",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      ".isecltrustTag",
						Operator: "In",
						Values:   []string{"test_data"},
					},
				},
				claims: jwt.MapClaims{
					"trustTag": claimtest3,
				},
				trustprefix: ".isecl",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Test 5 case assetClaimsPresent" {
				fmt.Println("yes")
			}
			if got := ValidatePodWithHvsAnnotation(tt.args.nodeData, tt.args.claims, tt.args.trustprefix); got != tt.want {
				t.Errorf("ValidatePodWithHvsAnnotation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateNodeByTime(t *testing.T) {

	currentTime := time.Now().UTC().Format(time.RFC3339)

	start := time.Now().UTC()
	end := start.Add(5 * time.Hour).UTC()

	type args struct {
		claims  jwt.MapClaims
		validTo string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Valid time",
			args: args{
				claims:  jwt.MapClaims{"validTo": currentTime},
				validTo: "validTo",
			},
			want: false,
		},
		{
			name: "Time expired",
			args: args{
				claims:  jwt.MapClaims{"validTo": end.String()},
				validTo: "validTo",
			},
			want: false,
		},
		{
			name: "Claim not found",
			args: args{
				claims:  jwt.MapClaims{"validTo": ""},
				validTo: "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateNodeByTime(tt.args.claims, tt.args.validTo); got != tt.want {
				t.Errorf("ValidateNodeByTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePodWithSgxAnnotation(t *testing.T) {

	claimtest := map[string]interface{}{"sgxEnabled": "test_data", "sgxSupported": "test_data", "tcbUpToDate": "test_data", "epcSize": "test_data", "flcEnabled": "test_data"}
	type args struct {
		nodeData    []v1.NodeSelectorRequirement
		claims      jwt.MapClaims
		trustprefix string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test 1",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      ".isecl",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims:      jwt.MapClaims{},
				trustprefix: ".isecl",
			},
			want: true,
		},
		{
			name: "test 2 SGX-Enabled",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      "yesSGX-Enabled",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims:      claimtest,
				trustprefix: "yes",
			},
			want: false,
		},
		{
			name: "test 3 SGX-Supported",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      "yesSGX-Supported",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims:      claimtest,
				trustprefix: "yes",
			},
			want: false,
		},
		{
			name: "test 4 TCBUpToDate",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      "yesTCBUpToDate",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims:      claimtest,
				trustprefix: "yes",
			},
			want: false,
		},
		{
			name: "test 5 EPC-Memory",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      "yesEPC-Memory",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims:      claimtest,
				trustprefix: "yes",
			},
			want: false,
		},
		{
			name: "test 5 FLC-Enabled",
			args: args{
				nodeData: []v1.NodeSelectorRequirement{
					v1.NodeSelectorRequirement{
						Key:      "yesFLC-Enabled",
						Operator: "In",
						Values:   []string{"a4bf01694f20.jf.intel.com"},
					},
				},
				claims:      claimtest,
				trustprefix: "yes",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidatePodWithSgxAnnotation(tt.args.nodeData, tt.args.claims, tt.args.trustprefix); got != tt.want {
				t.Errorf("ValidatePodWithSgxAnnotation() = %v, want %v", got, tt.want)
			}
		})
	}
}
