/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package crdController

import (
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/constants"
	trustschema "github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-controller/crdSchema/api/hostattribute/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"reflect"
	"testing"
	"time"
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
