/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/slice"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
)

type KeyTransferPolicyController struct {
	policyStore domain.KeyTransferPolicyStore
	keyStore    domain.KeyStore
}

func NewKeyTransferPolicyController(ps domain.KeyTransferPolicyStore, ks domain.KeyStore) *KeyTransferPolicyController {
	return &KeyTransferPolicyController{
		policyStore: ps,
		keyStore:    ks,
	}
}

//Create : Function to create a key transfer policy
func (ktpc *KeyTransferPolicyController) Create(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_policy_controller:Create() Entering")
	defer defaultLog.Trace("controllers/key_transfer_policy_controller:Create() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/key_transfer_policy_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var requestPolicy kbs.KeyTransferPolicy
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&requestPolicy)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_transfer_policy_controller:Create() %s : Unable to decode JSON request body", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := ValidateKeyTransferPolicy(requestPolicy); err != nil {
		secLog.WithError(err).Error("controllers/key_transfer_policy_controller:Create() Input validation failed")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Input validation failed"}
	}

	createdPolicy, err := ktpc.policyStore.Create(&requestPolicy)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/key_transfer_policy_controller:Create() Key transfer policy create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create key transfer policy"}
	}

	secLog.WithField("Id", createdPolicy.ID).Infof("controllers/key_transfer_policy_controller:Create() %s: Key Transfer Policy created by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	return createdPolicy, http.StatusCreated, nil
}

//Retrieve : Function to retrieve a key transfer policy
func (ktpc *KeyTransferPolicyController) Retrieve(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_policy_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/key_transfer_policy_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	transferPolicy, err := ktpc.policyStore.Retrieve(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Errorf("controllers/key_transfer_policy_controller:Retrieve() Key transfer policy with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Key transfer policy with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/key_transfer_policy_controller:Retrieve() Key transfer policy retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key transfer policy"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/key_transfer_policy_controller:Retrieve() %s: Key Transfer Policy retrieved by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
	return transferPolicy, http.StatusOK, nil
}

//Delete : Function to delete a key transfer policy
func (ktpc *KeyTransferPolicyController) Delete(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_policy_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/key_transfer_policy_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	criteria := &models.KeyFilterCriteria{
		TransferPolicyId: id,
	}

	keys, err := ktpc.keyStore.Search(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/key_transfer_policy_controller:Delete() Key search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search keys"}
	}

	if len(keys) > 0 {
		defaultLog.Error("controllers/key_transfer_policy_controller:Delete() Key transfer policy is associated with existing keys")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Key transfer policy is associated with keys"}
	}

	err = ktpc.policyStore.Delete(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/key_transfer_policy_controller:Delete() Key transfer policy with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Key transfer policy with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/key_transfer_policy_controller:Delete() Key transfer policy delete failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete key transfer policy"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/key_transfer_policy_controller:Delete() Key Transfer Policy deleted by: %s", request.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

//Search : Function to retrieve all the key transfer policies
func (ktpc *KeyTransferPolicyController) Search(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_policy_controller:Search() Entering")
	defer defaultLog.Trace("controllers/key_transfer_policy_controller:Search() Leaving")

	var criteria *models.KeyTransferPolicyFilterCriteria
	// Get All Key Transfer Policy Files
	transferPolicies, err := ktpc.policyStore.Search(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/key_transfer_policy_controller:Search() Key transfer policy search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search key transfer policies"}
	}

	secLog.Infof("controllers/key_transfer_policy_controller:Search() %s: Key Transfer Policies searched by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
	return transferPolicies, http.StatusOK, nil
}

func ValidateKeyTransferPolicy(requestPolicy kbs.KeyTransferPolicy) error {
	defaultLog.Trace("controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() Entering")
	defer defaultLog.Trace("controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() Leaving")

	if requestPolicy.AttestationType == nil {
		return errors.New("controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() Attestation_type must be specified")
	}

	if len(requestPolicy.AttestationType) != 1 {
		return errors.New("controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() Only one attestation type is supported in key transfer policy")
	}

	if !requestPolicy.AttestationType[0].Valid() {
		return errors.New("controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() Invalid attestation type")
	}

	if slice.Contains(requestPolicy.AttestationType, aps.SGX) && requestPolicy.SGX.Attributes != nil {
		if requestPolicy.SGX.Attributes.MrSigner == nil || requestPolicy.SGX.Attributes.IsvProductId == nil {
			return errors.New("controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() MrSigner and IsvProductId must be specified for SGX policy")
		}
		if err := ValidateSGXAttributes(requestPolicy.SGX.Attributes); err != nil {
			return errors.Wrap(err, "controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() Input validation failed for SGX Attributes")
		}
	}

	if slice.Contains(requestPolicy.AttestationType, aps.TDX) && requestPolicy.TDX.Attributes != nil {
		if requestPolicy.TDX.Attributes.MrSignerSeam == nil || requestPolicy.TDX.Attributes.MrSeam == nil {
			return errors.New("controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() MrSignerSeam and MrSeam must be specified for TDX policy")
		}
		if err := ValidateTDXAttributes(requestPolicy.TDX.Attributes); err != nil {
			return errors.Wrap(err, "controllers/key_transfer_policy_controller:ValidateKeyTransferPolicy() Input validation failed for TDX Attributes")
		}
	}
	return nil
}

func ValidateSGXAttributes(sgxPolicyAttributes *kbs.SgxAttributes) error {
	defaultLog.Trace("controllers/key_transfer_policy_controller:ValidateSGXAttributes() Entering")
	defer defaultLog.Trace("controllers/key_transfer_policy_controller:ValidateSGXAttributes() Leaving")

	for _, mrSigner := range sgxPolicyAttributes.MrSigner {
		if err := validation.ValidateSha256HexString(mrSigner); err != nil {
			return errors.Wrap(err, "Input validation failed for MR Signer")
		}
	}

	if sgxPolicyAttributes.MrEnclave != nil {
		for _, mrEnclave := range sgxPolicyAttributes.MrEnclave {
			if err := validation.ValidateSha256HexString(mrEnclave); err != nil {
				return errors.Wrap(err, "Input validation failed for MR Enclave")
			}
		}
	}

	if sgxPolicyAttributes.ClientPermissions != nil {
		if err := validation.ValidateStrings(sgxPolicyAttributes.ClientPermissions); err != nil {
			return errors.Wrap(err, "Input validation failed for client permissions")
		}
	}
	return nil
}

func ValidateTDXAttributes(tdxPolicyAttributes *kbs.TdxAttributes) error {
	defaultLog.Trace("controllers/key_transfer_policy_controller:ValidateTDXAttributes() Entering")
	defer defaultLog.Trace("controllers/key_transfer_policy_controller:ValidateTDXAttributes() Leaving")

	for _, mrSignerSeam := range tdxPolicyAttributes.MrSignerSeam {
		if err := validation.ValidateSha384HexString(mrSignerSeam); err != nil {
			return errors.Wrap(err, "Input validation failed for MR Signer seam")
		}
	}

	for _, mrSeam := range tdxPolicyAttributes.MrSeam {
		if err := validation.ValidateSha384HexString(mrSeam); err != nil {
			return errors.Wrap(err, "Input validation failed for MR Seam")
		}
	}

	if tdxPolicyAttributes.MRTD != nil {
		for _, mrTd := range tdxPolicyAttributes.MRTD {
			if err := validation.ValidateSha384HexString(mrTd); err != nil {
				return errors.Wrap(err, "Input validation failed for MRTD")
			}
		}
	}

	if tdxPolicyAttributes.RTMR0 != "" {
		if err := validation.ValidateSha384HexString(tdxPolicyAttributes.RTMR0); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR0")
		}
	}

	if tdxPolicyAttributes.RTMR1 != "" {
		if err := validation.ValidateSha384HexString(tdxPolicyAttributes.RTMR1); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR1")
		}
	}

	if tdxPolicyAttributes.RTMR2 != "" {
		if err := validation.ValidateSha384HexString(tdxPolicyAttributes.RTMR2); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR2")
		}
	}

	if tdxPolicyAttributes.RTMR3 != "" {
		if err := validation.ValidateSha384HexString(tdxPolicyAttributes.RTMR3); err != nil {
			return errors.Wrap(err, "Input validation failed for RTMR3")
		}
	}

	return nil
}
