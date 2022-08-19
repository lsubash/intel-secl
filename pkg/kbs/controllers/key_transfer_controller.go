/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/xml"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keytransfer"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/saml"
)

type KeyTransferController struct {
	remoteManager *keymanager.RemoteManager
	policyStore   domain.KeyTransferPolicyStore
	keyConfig     domain.KeyTransferControllerConfig
}

func NewKeyTransferController(rm *keymanager.RemoteManager, ps domain.KeyTransferPolicyStore, kc domain.KeyTransferControllerConfig) *KeyTransferController {
	return &KeyTransferController{
		remoteManager: rm,
		policyStore:   ps,
		keyConfig:     kc,
	}
}

// TransferWithSaml : Function to perform key transfer with saml report
func (kc *KeyTransferController) TransferWithSaml(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_controller:TransferWithSaml() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:TransferWithSaml() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypeSaml {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/key_transfer_controller:TransferWithSaml() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	bytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_transfer_controller:TransferWithSaml() %s : Unable to read request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to read request body"}
	}

	// Unmarshal saml report in request
	var samlReport *saml.Saml
	err = xml.Unmarshal(bytes, &samlReport)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_transfer_controller:TransferWithSaml() %s : SAML report unmarshal failed", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to unmarshal SAML report"}
	}

	// Validate saml report in request
	keyId := uuid.MustParse(mux.Vars(request)["id"])
	trusted, bindingCert := keytransfer.IsTrustedByHvs(string(bytes), samlReport, keyId, kc.keyConfig, kc.remoteManager)
	if !trusted {
		secLog.Error("controllers/key_transfer_controller:TransferWithSaml() Client not trusted by HVS")
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Client not trusted by HVS"}
	}
	envelopeKey := bindingCert.PublicKey.(*rsa.PublicKey)

	secretKey, status, err := getSecretKey(kc.remoteManager, keyId)
	if err != nil {
		return nil, status, err
	}

	// Wrap secret key with binding key
	wrappedKey, status, err := wrapKey(envelopeKey, secretKey.([]byte), sha256.New(), []byte("TPM2\000"))
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("Id", keyId).Infof("controllers/key_transfer_controller:TransferWithSaml() %s: Key transferred using SAML report by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
	return wrappedKey, http.StatusOK, nil
}
