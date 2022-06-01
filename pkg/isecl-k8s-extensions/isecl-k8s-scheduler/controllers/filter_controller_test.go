/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package controllers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/constants"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	schedulerapi "k8s.io/kube-scheduler/extender/v1"
)

const (
	EnvelopePublickeyLocationIseclk8sScheduler = "../../test_utility/isecl-k8s-scheduler/envelopePublicKey.pem"
)

func TestFilterHandler_Filter(t *testing.T) {

	pubkey, _ := ioutil.ReadFile(EnvelopePublickeyLocationIseclk8sScheduler)

	responseWri := httptest.NewRecorder()

	label := make(map[string]string)
	annotation := make(map[string]string)

	testNode := &v1.Node{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "node-test",
			GenerateName:    "node-test-extension",
			SelfLink:        "",
			UID:             "0ca7b97f4e4b48c8a33566dd86d8e33d",
			ResourceVersion: "",
			Generation:      1,
			ClusterName:     "clusterTest",
			Labels:          label,
			Annotations:     annotation,
		},
		Spec: v1.NodeSpec{
			PodCIDR:       "",
			PodCIDRs:      []string{"1", "2", "3"},
			ProviderID:    "",
			Unschedulable: true,
			Taints: []v1.Taint{{
				Key:   "test-taint",
				Value: "taint-value",
			},
			},
		},
		Status: v1.NodeStatus{
			Capacity: v1.ResourceList{},
		},
	}

	extendedArgs := schedulerapi.ExtenderArgs{
		Pod: &v1.Pod{
			Spec: v1.PodSpec{
				Affinity: &v1.Affinity{
					NodeAffinity: &v1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
							NodeSelectorTerms: []v1.NodeSelectorTerm{
								{
									MatchExpressions: []v1.NodeSelectorRequirement{
										v1.NodeSelectorRequirement{
											Key:      "metadata.name",
											Operator: "In",
											Values:   []string{"a4bf01694f20.jf.intel.com"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Nodes: &v1.NodeList{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "apps/v1",
			},
			ListMeta: metav1.ListMeta{},
			Items:    []v1.Node{*testNode},
		},
		NodeNames: &[]string{"node-test"},
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(extendedArgs)

	if err != nil {
		assert.NoError(t, err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		&buf,
	)
	if err != nil {
		assert.NoError(t, err)
	}

	extendedArgsWithoutNodelist := schedulerapi.ExtenderArgs{
		Pod: &v1.Pod{
			Spec: v1.PodSpec{
				Affinity: &v1.Affinity{
					NodeAffinity: &v1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
							NodeSelectorTerms: []v1.NodeSelectorTerm{
								{
									MatchExpressions: []v1.NodeSelectorRequirement{
										v1.NodeSelectorRequirement{
											Key:      "metadata.name",
											Operator: "In",
											Values:   []string{"a4bf01694f20.jf.intel.com"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Nodes:     &v1.NodeList{},
		NodeNames: &[]string{"node-test"},
	}

	var bufWithoutNodelist bytes.Buffer
	err = json.NewEncoder(&bufWithoutNodelist).Encode(extendedArgsWithoutNodelist)

	if err != nil {
		assert.NoError(t, err)
	}

	reqWithoutNodelist, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		&bufWithoutNodelist,
	)
	if err != nil {
		assert.NoError(t, err)
	}

	nilbody, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		nil,
	)
	if err != nil {
		assert.NoError(t, err)
	}

	var fakebuf bytes.Buffer
	err = json.NewEncoder(&fakebuf).Encode("#@!$")

	if err != nil {
		assert.NoError(t, err)
	}

	wrongreq, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		&fakebuf,
	)

	if err != nil {
		assert.NoError(t, err)
	}

	type fields struct {
		ResourceStore ResourceStore
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Should pass for valid request",
			fields: fields{
				ResourceStore: ResourceStore{
					IHubPubKeys: map[string][]byte{"HVS": pubkey},
					TagPrefix:   ".isecl",
				},
			},
			args: args{
				w: responseWri,
				r: req,
			},
		},
		{
			name: "Should fail for nil body in request",
			fields: fields{
				ResourceStore: ResourceStore{
					IHubPubKeys: map[string][]byte{"HVS": pubkey},
					TagPrefix:   ".isecl",
				},
			},
			args: args{
				w: responseWri,
				r: nilbody,
			},
		},
		{
			name: "Should fail for invalid request",
			fields: fields{
				ResourceStore: ResourceStore{
					IHubPubKeys: map[string][]byte{"HVS": pubkey},
					TagPrefix:   ".isecl",
				},
			},
			args: args{
				w: responseWri,
				r: wrongreq,
			},
		},
		{
			name: "Should fail in filtered host for empty node list",
			fields: fields{
				ResourceStore: ResourceStore{
					IHubPubKeys: map[string][]byte{"HVS": pubkey},
					TagPrefix:   ".isecl",
				},
			},
			args: args{
				w: responseWri,
				r: reqWithoutNodelist,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &FilterHandler{
				ResourceStore: tt.fields.ResourceStore,
			}
			f.Filter(tt.args.w, tt.args.r)
		})
	}
}
