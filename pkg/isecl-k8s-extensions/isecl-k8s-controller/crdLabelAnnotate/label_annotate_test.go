/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package crdLabelAnnotate

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

func TestGetk8sClientHelper(t *testing.T) {
	type args struct {
		config *rest.Config
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Should fail for k8sclient.NewForConfig",
			args: args{
				config: &rest.Config{
					Host:    "",
					APIPath: "",
					ContentConfig: rest.ContentConfig{
						AcceptContentTypes: "",
					},
				},
			},
		},
		{
			name: "Valid case should pass",
			args: args{
				config: &rest.Config{
					Host:    "",
					APIPath: "",
					ContentConfig: rest.ContentConfig{
						AcceptContentTypes: "",
					},
					RateLimiter: nil,
					QPS:         5,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = Getk8sClientHelper(tt.args.config)
		})
	}
}

func Test_AddLabelsAnnotations(t *testing.T) {

	node, _, err := createFakeNode()
	if err != nil {
		assert.NoError(t, errors.New("Error in creating fake node"))
	}

	type args struct {
		n           *corev1.Node
		labels      Labels
		annotations Annotations
		labelPrefix string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Valid case - Applying labels and annotations to the node",
			args: args{
				n: node,
				labels: Labels{
					"node":  "test",
					"node1": "test1",
					"node2": "test2",
				},
				annotations: Annotations{
					"kubeadm.alpha.kubernetes.io/cri-socket": "/var/run/dockershim.sock",
				},
				labelPrefix: "test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddLabelsAnnotations(tt.args.n, tt.args.labels, tt.args.annotations, tt.args.labelPrefix)
		})
	}
}

func Test_AddTaint(t *testing.T) {

	node, _, err := createFakeNode()
	if err != nil {
		assert.NoError(t, errors.New("Error in creating fake node"))
	}

	type args struct {
		n      *corev1.Node
		key    string
		value  string
		effect string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Should be successful in adding taint",
			args: args{
				n:      node,
				key:    "test-taint-2",
				value:  "changeTaint",
				effect: "NoSchedule",
			},
			wantErr: false,
		},
		{
			name: "Should fail for invalid effect send through args",
			args: args{
				n:      node,
				key:    "test-taint-3",
				value:  "changeTaint",
				effect: "invalidEffect",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := AddTaint(tt.args.n, tt.args.key, tt.args.value, tt.args.effect); (err != nil) != tt.wantErr {
				t.Errorf("K8sHelpers.AddTaint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_DeleteTaint(t *testing.T) {

	node, _, err := createFakeNode()
	if err != nil {
		assert.NoError(t, errors.New("Error in creating fake node"))
	}

	type argsAddTaint struct {
		n      *corev1.Node
		key    string
		value  string
		effect string
	}

	testAddTaint := struct {
		args argsAddTaint
	}{
		args: argsAddTaint{
			n:      node,
			key:    "test-taint-add",
			value:  "test",
			effect: "NoSchedule",
		},
	}

	err = AddTaint(testAddTaint.args.n, testAddTaint.args.key, testAddTaint.args.value, testAddTaint.args.effect)
	if err != nil {
		assert.NoError(t, err)
	}

	type args struct {
		n      *corev1.Node
		key    string
		value  string
		effect string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Should pass, if taint not present, will be added to new list",
			args: args{
				n:      node,
				key:    "test-taint-2",
				value:  "changeTaint",
				effect: "NoSchedule",
			},
			wantErr: false,
		},
		{
			name: "Should fail for invalid taint effect",
			args: args{
				n:      node,
				key:    "test-taint-3",
				value:  "changeTaint",
				effect: "invalidEffect",
			},
			wantErr: true,
		},
		{
			name: "Should pass, taint is present, so delete",
			args: args{
				n:      node,
				key:    "test-taint-add",
				value:  "test",
				effect: "NoSchedule",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := DeleteTaint(tt.args.n, tt.args.key, tt.args.value, tt.args.effect); (err != nil) != tt.wantErr {
				t.Errorf("K8sHelpers.DeleteTaint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
