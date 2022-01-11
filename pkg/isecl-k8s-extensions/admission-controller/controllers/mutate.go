/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package controllers

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/constants"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"io/ioutil"
	admission "k8s.io/api/admission/v1"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"net/http"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// HandleMutate handles the mutate
func HandleMutate(w http.ResponseWriter, r *http.Request) {

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defaultLog.WithError(err).Error("Error reading admission controller body")
		return
	}

	var admissionReviewReq admission.AdmissionReview

	universalDeserializer := serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()

	//To convert the request body into struct
	if _, _, err := universalDeserializer.Decode(body, nil, &admissionReviewReq); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		defaultLog.Errorf("could not deserialize request: %v", err)
		return
	} else if admissionReviewReq.Request == nil {
		w.WriteHeader(http.StatusBadRequest)
		defaultLog.Error("malformed admission review: request is nil")
		return
	}

	var node apiv1.Node
	var noScheduleTaint apiv1.Taint
	var noExecuteTaint apiv1.Taint

	err = json.Unmarshal(admissionReviewReq.Request.Object.Raw, &node)

	if err != nil {
		defaultLog.Errorf("could not unmarshal node on admission request: %v", err)
		return
	}

	defaultLog.Debugf("node is %v", node)

	taints := node.Spec.Taints
	noScheduleTaint.Key = constants.TaintNameNoschedule
	noScheduleTaint.Value = constants.TaintValueTrue
	noScheduleTaint.Effect = constants.TaintEffectNoSchedule

	noExecuteTaint.Key = constants.TaintNameNoexecute
	noExecuteTaint.Value = constants.TaintValueTrue
	noExecuteTaint.Effect = constants.TaintEffectNoExecute

	taints = append(taints, noScheduleTaint)
	taints = append(taints, noExecuteTaint)

	var patches []patchOperation

	patches = append(patches, patchOperation{
		Op:    "add",
		Path:  "/spec/taints",
		Value: taints,
	})

	//convert to byte array
	patchBytes, err := json.Marshal(patches)
	if err != nil {
		defaultLog.Errorf("could not marshal JSON patch: %v", err)
		return
	}

	admissionReviewResponse := admission.AdmissionReview{
		Response: &admission.AdmissionResponse{
			UID:     admissionReviewReq.Request.UID,
			Allowed: true,
		},
	}

	admissionReviewResponse.Response.Patch = patchBytes
	bytes, err := json.Marshal(&admissionReviewResponse)
	if err != nil {
		defaultLog.Errorf("Error while marshaling response: %v", err)
		return
	}

	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Write(bytes)
	defaultLog.Infof("Successfully added taint to Node %v", node.Name)
}
