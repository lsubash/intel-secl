/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	admission "k8s.io/api/admission/v1"

	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/constants"
	"github.com/stretchr/testify/assert"
	apiv1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func TestHandleMutate(t *testing.T) {

	label := make(map[string]string)
	annotation := make(map[string]string)
	node := &apiv1.Node{
		TypeMeta: v1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ObjectMeta: v1.ObjectMeta{
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
		Spec: apiv1.NodeSpec{
			PodCIDR:       "",
			PodCIDRs:      []string{"1", "2", "3"},
			ProviderID:    "",
			Unschedulable: true,
			Taints: []apiv1.Taint{{
				Key:   "test-taint",
				Value: "taint-value",
			},
			},
		},
		Status: apiv1.NodeStatus{
			Capacity: apiv1.ResourceList{},
		},
	}

	nodeBytes, err := json.Marshal(node)
	if err != nil {
		assert.NoError(t, err)
	}

	admissionReviewReq := admission.AdmissionReview{
		TypeMeta: v1.TypeMeta{},
		Request: &admission.AdmissionRequest{
			Object: runtime.RawExtension{
				Raw: nodeBytes,
			},
		},
		Response: &admission.AdmissionResponse{},
	}

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(admissionReviewReq)

	if err != nil {
		assert.NoError(t, err)
	}

	responseWri := httptest.NewRecorder()
	req, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		&buf,
	)

	if err != nil {
		assert.NoError(t, err)
	}

	var nodeUnmarshallFailurebuf bytes.Buffer
	err = json.NewEncoder(&nodeUnmarshallFailurebuf).Encode("@@##$$")

	if err != nil {
		assert.NoError(t, err)
	}

	nodeUnmarshallFailurereq, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		&nodeUnmarshallFailurebuf,
	)

	if err != nil {
		assert.NoError(t, err)
	}

	nilBodyreq, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		errReader(0),
	)

	invalidReq := struct {
		name string
	}{
		name: "Test",
	}

	var invalidReqbuf bytes.Buffer
	err = json.NewEncoder(&invalidReqbuf).Encode(invalidReq)

	if err != nil {
		assert.NoError(t, err)
	}

	invalidBodyReq, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		&invalidReqbuf,
	)

	invalidNodeBytes, err := json.Marshal("@@@##")
	if err != nil {
		assert.NoError(t, err)
	}

	admissionReviewReqWithInvalidNodeData := admission.AdmissionReview{
		TypeMeta: v1.TypeMeta{},
		Request: &admission.AdmissionRequest{
			Object: runtime.RawExtension{
				Raw: invalidNodeBytes,
			},
		},
		Response: &admission.AdmissionResponse{},
	}

	var invalidNodeBuf bytes.Buffer
	err = json.NewEncoder(&invalidNodeBuf).Encode(admissionReviewReqWithInvalidNodeData)

	if err != nil {
		assert.NoError(t, err)
	}

	invalidNodeReq, err := http.NewRequest(
		http.MethodPost,
		constants.MutateRoute,
		&invalidNodeBuf,
	)

	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Valid case should pass",
			args: args{
				w: responseWri,
				r: req,
			},
		},
		{
			name: "Should fail for unmarshalling node data",
			args: args{
				w: responseWri,
				r: nodeUnmarshallFailurereq,
			},
		},
		{
			name: "Should fail for nil body in request",
			args: args{
				w: responseWri,
				r: nilBodyreq,
			},
		},
		{
			name: "Should fail for invalid body in request",
			args: args{
				w: responseWri,
				r: invalidBodyReq,
			},
		},
		{
			name: "Should fail for invalid node data",
			args: args{
				w: responseWri,
				r: invalidNodeReq,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			HandleMutate(tt.args.w, tt.args.r)
		})
	}
}
