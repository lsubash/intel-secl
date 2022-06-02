/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package algorithm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	schedulerapi "k8s.io/kube-scheduler/extender/v1"
)

const (
	EnvelopePublickeyLocationIseclk8sScheduler  = "../../test_utility/isecl-k8s-scheduler/envelopePublicKey.pem"
	EnvelopePrivatekeyLocationIseclk8sScheduler = "../../test_utility/isecl-k8s-scheduler/envelopePrivateKey.pem"
)

func getDuplicateCipherAnnotation(t *testing.T) string {

	jwtHeader := JwtHeader{
		KeyId:     "9VEIrsLPkhR4DWDMNRTsZmBVfJVcjLsXHOHgt5K/jvWLWqEWlZhrDG5VwOEIwlPa",
		Type:      "",
		Algorithm: "HS256",
	}

	j, err := json.Marshal(jwtHeader)
	if err != nil {
		assert.NoError(t, err)
	}

	type data struct {
		name string
	}

	testdata := data{
		name: "sampledata",
	}

	marshalledtestdata, err := json.Marshal(testdata)
	if err != nil {
		assert.NoError(t, err)
	}

	encodedCipherText := base64.URLEncoding.EncodeToString(j)
	encodedTestData := base64.URLEncoding.EncodeToString(marshalledtestdata)

	pvtKey, _ := ioutil.ReadFile(EnvelopePrivatekeyLocationIseclk8sScheduler)
	signature := getSignature(t, pvtKey, encodedCipherText, encodedTestData)
	encodedSignature := base64.URLEncoding.EncodeToString((signature))

	encodedCipherText = encodedCipherText + "." + encodedTestData + "." + encodedSignature

	return encodedCipherText
}

func getSignature(t *testing.T, privKeyPEM []byte, encodedCipherText string, testdata string) []byte {

	data := encodedCipherText + "." + testdata

	// Parse private key into rsa.PrivateKey
	PEMBlock, _ := pem.Decode((privKeyPEM))
	if PEMBlock == nil {
		assert.NoError(t, errors.New("Could not parse Private Key PEM"))
	}
	if PEMBlock.Type != "PRIVATE KEY" {
		assert.NoError(t, errors.New("Found wrong key type"))
	}
	privkey, err := x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
	if err != nil {
		assert.NoError(t, err)
	}

	h := sha512.New384()
	h.Write([]byte(data))

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA384, h.Sum(nil))
	if err != nil {
		assert.NoError(t, err)
	}

	return signature
}

func TestFilteredHost(t *testing.T) {

	ann := getDuplicateCipherAnnotation(t)
	pubkey, _ := ioutil.ReadFile(EnvelopePublickeyLocationIseclk8sScheduler)

	label := make(map[string]string)
	hvsannotation := map[string]string{"HvsSignedTrustReport": ann}
	sgxannotation := map[string]string{"SgxSignedTrustReport": ann}
	fakeannotation := map[string]string{"FakeReport": ann}

	hvsTestNode := &v1.Node{
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
			Annotations:     hvsannotation,
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

	TestNodeWithFakeAnnotation := &v1.Node{
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
			Annotations:     fakeannotation,
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

	sgxTestNode := &v1.Node{
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
			Annotations:     sgxannotation,
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

	hvstestNodeList := v1.NodeList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ListMeta: metav1.ListMeta{},
		Items:    []v1.Node{*hvsTestNode},
	}

	sgxtestNodeList := v1.NodeList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ListMeta: metav1.ListMeta{},
		Items:    []v1.Node{*sgxTestNode},
	}

	hvsAndSgxNodeList := v1.NodeList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ListMeta: metav1.ListMeta{},
		Items:    []v1.Node{*sgxTestNode, *hvsTestNode},
	}

	nodeListWithFakeAnnotation := v1.NodeList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "apps/v1",
		},
		ListMeta: metav1.ListMeta{},
		Items:    []v1.Node{*TestNodeWithFakeAnnotation},
	}

	affinityNilPod := &v1.Pod{
		Spec: v1.PodSpec{
			Affinity: nil,
		},
	}

	testPod := &v1.Pod{
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
	}

	testPodWithNil := &v1.Pod{
		Spec: v1.PodSpec{
			Affinity: &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: nil,
				},
			},
		},
	}

	type args struct {
		args        *schedulerapi.ExtenderArgs
		iHubPubKeys map[string][]byte
		tagPrefix   string
	}
	tests := []struct {
		name    string
		args    args
		want    *schedulerapi.ExtenderFilterResult
		wantErr bool
	}{
		{
			name: "Test 1 affinityNilPod",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:   affinityNilPod,
					Nodes: &hvstestNodeList,
				},
			},
			wantErr: false,
		},
		{
			name: "Test 2 node validation failure",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:       testPod,
					Nodes:     &v1.NodeList{},
					NodeNames: &[]string{"node-test"},
				},
				iHubPubKeys: map[string][]byte{},
				tagPrefix:   ".isecl",
			},
			wantErr: true,
		},
		{
			name: "Test 3 HVS attestation",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:       testPod,
					Nodes:     &hvstestNodeList,
					NodeNames: &[]string{"node-test"},
				},
				iHubPubKeys: map[string][]byte{"HVS": pubkey},
				tagPrefix:   ".isecl",
			},
			wantErr: false,
		},
		{
			name: "Test 4 SGX attestation",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:       testPod,
					Nodes:     &sgxtestNodeList,
					NodeNames: &[]string{"node-test"},
				},
				iHubPubKeys: map[string][]byte{"SGX": pubkey},
				tagPrefix:   ".isecl",
			},
			wantErr: false,
		},
		{
			name: "Test 5 HVS attestation with nil pubkey",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:       testPod,
					Nodes:     &hvstestNodeList,
					NodeNames: &[]string{"node-test"},
				},
				iHubPubKeys: map[string][]byte{"HVS": nil},
				tagPrefix:   ".isecl",
			},
			wantErr: true,
		},
		{
			name: "Test 6 SGX attestation with nil pubkey",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:       testPod,
					Nodes:     &sgxtestNodeList,
					NodeNames: &[]string{"node-test"},
				},
				iHubPubKeys: map[string][]byte{"SGX": nil},
				tagPrefix:   ".isecl",
			},
			wantErr: true,
		},
		{
			name: "Test 7 HVS and SGX attestation together",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:       testPod,
					Nodes:     &hvsAndSgxNodeList,
					NodeNames: &[]string{"node-test"},
				},
				iHubPubKeys: map[string][]byte{"SGX": pubkey, "HVS": pubkey},
				tagPrefix:   ".isecl",
			},
			wantErr: false,
		},
		{
			name: "Test 8 NodeSelector nil pod",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:   testPodWithNil,
					Nodes: &hvstestNodeList,
				},
			},
			wantErr: false,
		},
		{
			name: "Test 9 nodeListWithFakeAnnotation",
			args: args{
				args: &schedulerapi.ExtenderArgs{
					Pod:   testPod,
					Nodes: &nodeListWithFakeAnnotation,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FilteredHost(tt.args.args, tt.args.iHubPubKeys, tt.args.tagPrefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilteredHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
