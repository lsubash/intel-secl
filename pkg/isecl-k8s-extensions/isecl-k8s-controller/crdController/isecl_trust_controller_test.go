/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package crdController

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/crdLabelAnnotate"
	ha_schema "github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/crdSchema/api/hostattribute/v1beta1"
	trustschema "github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/crdSchema/api/hostattribute/v1beta1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	tagPrefixConfContents = `{"trusted":"isecl."}`
)

func TestGetPlCrdDef(t *testing.T) {
	expectPlCrd := CrdDefinition{
		Plural:   "hostattributes",
		Singular: "hostattribute",
		Group:    "crd.isecl.intel.com",
		Kind:     "HostAttributeCrd",
	}
	recvPlCrd := GetHACrdDef()
	if reflect.DeepEqual(expectPlCrd, recvPlCrd) {
		t.Errorf("Expected :%v however Received: %v ", expectPlCrd, recvPlCrd)
	}
	t.Logf("Test GetPLCrd Def success")
}

func TestGetPlObjLabel(t *testing.T) {
	trustObj := trustschema.Host{
		Hostname:             "Node123",
		Trusted:              true,
		HvsTrustExpiry:       time.Now().AddDate(1, 0, 0),
		HvsSignedTrustReport: "495270d6242e2c67e24e22bad49dgdah",
		SgxSignedTrustReport: "495270d6242e2c67e24e22bad49dgdah",
		AssetTag: map[string]string{
			"trusted":      "true",
			"country.us":   "true",
			"country.uk":   "true",
			"state.ca":     "true",
			"city.seattle": "true",
		},
	}

	node := &corev1.Node{}

	recvlabel, recannotate, _ := GetHaObjLabel(trustObj, node, constants.TagPrefixDefault)
	prefix := "isecl."
	if _, ok := recvlabel[prefix+trustlabel]; ok {
		t.Logf("Found in HA label Trusted field")
	} else {
		t.Fatalf("Could not get label trusted from HA Report")
	}
	if _, ok := recvlabel[prefix+"country.us"]; ok {
		t.Logf("Found HA label in AssetTag report")
	} else {
		t.Fatalf("Could not get required label from HA Report")
	}
	if _, ok := recvlabel[hvsTrustExpiry]; ok {
		t.Logf("Found in HA label TrustTagExpiry field")
	} else {
		t.Fatalf("Could not get label TrustTagExpiry from HA Report")
	}
	if _, ok := recannotate[hvsSignTrustReport]; ok {
		t.Logf("Found in HA annotation TrustTagSignedReport ")
	} else {
		t.Fatalf("Could not get annotation TrustTagSignedReport from HA Report")
	}
	t.Logf("Test getHaObjLabel success")
}

func TestNewIseclHAController(t *testing.T) {

	config := &rest.Config{
		Host:    "",
		APIPath: "",
	}
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), constants.WgName)

	indexer, informer := NewIseclHAIndexerInformer(config, queue, &sync.Mutex{}, "TAG_PREFIX")

	type args struct {
		queue    workqueue.RateLimitingInterface
		indexer  cache.Indexer
		informer cache.Controller
	}
	tests := []struct {
		name string
		args args
		want *IseclHAController
	}{
		{
			name: "Valid case in filling the data",
			args: args{
				queue:    queue,
				indexer:  indexer,
				informer: informer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewIseclHAController(tt.args.queue, tt.args.indexer, tt.args.informer)
		})
	}
}

func TestIseclHAController_processNextItem(t *testing.T) {

	q := createMockQueue()

	config := &rest.Config{
		Host:    "",
		APIPath: "",
	}

	TaintUntrustedNodes = constants.TaintUntrustedNodesDefault
	TaintRegisteredNodes = constants.TaintRegisteredNodesDefault
	TaintRebootedNodes = constants.TaintRebootedNodesDefault

	indexer, informer := NewIseclHAIndexerInformer(config, q, &sync.Mutex{}, "TAG_PREFIX")

	type fields struct {
		indexer  cache.Indexer
		informer cache.Controller
		queue    workqueue.RateLimitingInterface
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "Should pass for processing the item in queue",
			fields: fields{
				queue:    q,
				indexer:  indexer,
				informer: informer,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &IseclHAController{
				indexer:  tt.fields.indexer,
				informer: tt.fields.informer,
				queue:    tt.fields.queue,
			}
			_ = c.processNextItem()
		})
	}
}

func TestAddHostAttributesTabObj(t *testing.T) {

	node, _, err := createFakeNode()
	if err != nil {
		assert.NoError(t, errors.New("Error in creating fake node"))
	}
	helper, clientSet := NewMockGetk8sClientHelper()

	label := make(map[string]string)
	annotation := make(map[string]string)

	label["SGX-Enabled"] = "true"

	type args struct {
		haobj     *ha_schema.HostAttributesCrd
		helper    crdLabelAnnotate.APIHelpers
		cli       *k8sclient.Clientset
		mutex     *sync.Mutex
		tagPrefix string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "addition event of the HA CRD",
			args: args{
				haobj: &trustschema.HostAttributesCrd{
					TypeMeta: metav1.TypeMeta{
						Kind:       "node",
						APIVersion: "apps/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            node.Name,
						GenerateName:    "node-test-extension",
						Namespace:       "default",
						SelfLink:        "",
						UID:             "0ca7b97f4e4b48c8a33566dd86d8e33d",
						ResourceVersion: "",
						Generation:      1,
						ClusterName:     "clusterTest",
						Labels:          label,
						Annotations:     annotation,
					},
					Spec: trustschema.Spec{
						HostList: []trustschema.Host{{Hostname: node.Name, Trusted: true, SgxSignedTrustReport: "yes"}, {Hostname: "unknown", Trusted: false}},
					},
				},
				helper:    helper,
				cli:       &clientSet,
				mutex:     &sync.Mutex{},
				tagPrefix: "isecl.",
			},
		},
		{
			name: "either Taint or Remove the node with no execute",
			args: args{
				haobj: &trustschema.HostAttributesCrd{
					TypeMeta: metav1.TypeMeta{
						Kind:       "node",
						APIVersion: "apps/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            node.Name,
						GenerateName:    "node-test-extension",
						Namespace:       "default",
						SelfLink:        "",
						UID:             "0ca7b97f4e4b48c8a33566dd86d8e33d",
						ResourceVersion: "",
						Generation:      1,
						ClusterName:     "clusterTest",
						Labels:          label,
						Annotations:     annotation,
					},
					Spec: trustschema.Spec{
						HostList: []trustschema.Host{{Hostname: node.Name, Trusted: false, SgxSignedTrustReport: "yes"}, {Hostname: node.Name, Trusted: true}},
					},
				},
				helper:    helper,
				cli:       &clientSet,
				mutex:     &sync.Mutex{},
				tagPrefix: "isecl.",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "either Taint or Remove the node with no execute" {
				TaintUntrustedNodes = true
			}
			AddHostAttributesTabObj(tt.args.haobj, tt.args.helper, tt.args.cli, tt.args.mutex, tt.args.tagPrefix)
			TaintUntrustedNodes = false
		})
	}
}

func TestTaintNode(t *testing.T) {

	node, _, err := createFakeNode()
	if err != nil {
		assert.NoError(t, errors.New("Error in creating fake node"))
	}
	helper, clientSet := NewMockGetk8sClientHelper()

	type args struct {
		Mutex      *sync.Mutex
		nodeHelper crdLabelAnnotate.APIHelpers
		name       string
		cli        *k8sclient.Clientset
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Add taint to nodes",
			args: args{
				Mutex:      &sync.Mutex{},
				nodeHelper: helper,
				name:       node.Name,
				cli:        &clientSet,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			TaintNode(tt.args.Mutex, tt.args.nodeHelper, tt.args.name, tt.args.cli)
		})
	}
}

func TestIseclHAController_handleErr(t *testing.T) {

	q := createMockQueue()

	TaintUntrustedNodes = constants.TaintUntrustedNodesDefault
	TaintRegisteredNodes = constants.TaintRegisteredNodesDefault
	TaintRebootedNodes = constants.TaintRebootedNodesDefault

	indexer, informer := NewIseclHAIndexerInformer(&rest.Config{}, q, &sync.Mutex{}, "TAG_PREFIX")

	type fields struct {
		indexer  cache.Indexer
		informer cache.Controller
		queue    workqueue.RateLimitingInterface
	}
	type args struct {
		err error
		key interface{}
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test nil error",
			fields: fields{
				indexer:  indexer,
				informer: informer,
				queue:    q,
			},
			args: args{
				err: nil,
				key: "test-1",
			},
		},
		{
			name: "Test with error",
			fields: fields{
				indexer:  indexer,
				informer: informer,
				queue:    q,
			},
			args: args{
				err: errors.New("Error"),
				key: "test-1",
			},
		},
		{
			name: "Test with error and having data in queue",
			fields: fields{
				indexer:  indexer,
				informer: informer,
				queue:    q,
			},
			args: args{
				err: errors.New("Error"),
				key: "test-1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.name == "Test with error and having data in queue" {
				for i := 0; i < 4; i++ {
					tt.fields.queue.Add(i)
				}
			}
			c := &IseclHAController{
				indexer:  tt.fields.indexer,
				informer: tt.fields.informer,
				queue:    tt.fields.queue,
			}
			c.handleErr(tt.args.err, tt.args.key)
		})
	}
}

func TestNewIseclHAIndexerInformer(t *testing.T) {

	q := createMockQueue()

	TaintUntrustedNodes = constants.TaintUntrustedNodesDefault
	TaintRegisteredNodes = true
	TaintRebootedNodes = true

	type args struct {
		config    *rest.Config
		queue     workqueue.RateLimitingInterface
		crdMutex  *sync.Mutex
		tagPrefix string
	}
	tests := []struct {
		name  string
		args  args
		want  cache.Indexer
		want1 cache.Controller
	}{
		{
			name: "Should pass for filling the data",
			args: args{
				config:    &rest.Config{},
				queue:     q,
				crdMutex:  &sync.Mutex{},
				tagPrefix: "isecl.",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = NewIseclHAIndexerInformer(tt.args.config, tt.args.queue, tt.args.crdMutex, tt.args.tagPrefix)
		})
	}
}

func TestNewIseclTaintHAIndexerInformer(t *testing.T) {

	q := createMockQueue()

	TaintUntrustedNodes = constants.TaintUntrustedNodesDefault
	TaintRegisteredNodes = true
	TaintRebootedNodes = true

	type args struct {
		config    *rest.Config
		queue     workqueue.RateLimitingInterface
		Mutex     *sync.Mutex
		tagPrefix string
	}
	tests := []struct {
		name  string
		args  args
		want  cache.Indexer
		want1 cache.Controller
	}{
		{
			name: "Should pass for filling the data",
			args: args{
				config:    &rest.Config{},
				queue:     q,
				tagPrefix: "isecl.",
				Mutex:     &sync.Mutex{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = NewIseclTaintHAIndexerInformer(tt.args.config, tt.args.queue, tt.args.Mutex, tt.args.tagPrefix)
		})
	}
}
