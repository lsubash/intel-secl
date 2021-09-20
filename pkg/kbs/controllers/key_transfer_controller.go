/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/slice"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	apsc "github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	consts "github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keytransfer"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	jwtauth "github.com/intel-secl/intel-secl/v5/pkg/lib/common/jwt"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	cmw "github.com/intel-secl/intel-secl/v5/pkg/lib/common/middleware"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/saml"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
)

type KeyTransferController struct {
	remoteManager *keymanager.RemoteManager
	policyStore   domain.KeyTransferPolicyStore
	keyConfig     domain.KeyControllerConfig
	client        apsc.APSClient
}

var jwtVerifier jwtauth.Verifier

type RetrieveApsJwtCertFn func() error

const (
	ivSize   = 4
	tagSize  = 4
	wrapSize = 4
)

func NewKeyTransferController(rm *keymanager.RemoteManager, ps domain.KeyTransferPolicyStore, kc domain.KeyControllerConfig, ac apsc.APSClient) *KeyTransferController {
	return &KeyTransferController{
		remoteManager: rm,
		policyStore:   ps,
		keyConfig:     kc,
		client:        ac,
	}
}

//Transfer : Function to perform key transfer
func (kc *KeyTransferController) Transfer(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_controller:Transfer() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:Transfer() Leaving")

	keyId := uuid.MustParse(mux.Vars(request)["id"])
	key, err := kc.remoteManager.RetrieveKey(keyId)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.WithError(err).Error("controllers/key_transfer_controller:Transfer() Key with specified id doesn't exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Key with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/key_transfer_controller:Transfer() Key retrieval failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key"}
		}
	}

	if key.TransferPolicyID == kc.keyConfig.DefaultTransferPolicyId {
		defaultLog.Info("controllers/key_transfer_controller:Transfer() Key transfer request for SAML-based key transfer")

		if request.Header.Get("Content-Type") != constants.HTTPMediaTypeSaml {
			defaultLog.Error("controllers/key_transfer_controller:Transfer() Invalid Content-Type")
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
		}

		if request.ContentLength == 0 {
			secLog.Error("controllers/key_transfer_controller:Transfer() The request body was not provided")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
		}

		bytes, err := ioutil.ReadAll(request.Body)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/key_transfer_controller:Transfer() %s : Unable to read request body", commLogMsg.InvalidInputBadEncoding)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to read request body"}
		}

		// Unmarshal saml report in request
		var samlReport *saml.Saml
		err = xml.Unmarshal(bytes, &samlReport)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/key_transfer_controller:Transfer() %s : SAML report unmarshal failed", commLogMsg.InvalidInputBadParam)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to unmarshal SAML report"}
		}

		// Validate saml report in request
		trusted, bindingCert := keytransfer.IsTrustedByHvs(string(bytes), samlReport, keyId, kc.keyConfig, kc.remoteManager)
		if !trusted {
			secLog.Error("controllers/key_transfer_controller:Transfer() Client not trusted by HVS")
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

		transferResponse := kbs.KeyTransferResponse{
			WrappedKey: base64.StdEncoding.EncodeToString(wrappedKey.([]byte)),
		}

		secLog.WithField("Id", keyId).Infof("controllers/key_transfer_controller:Transfer() %s: Key transferred using SAML report by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
		return transferResponse, http.StatusOK, nil
	}

	transferPolicy, err := kc.policyStore.Retrieve(key.TransferPolicyID)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/key_transfer_controller:Transfer() Key transfer policy retrieve failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve key transfer policy"}
	}

	var keyTransferRequest kbs.KeyTransferRequest
	var cacheTime, _ = time.ParseDuration(consts.JWTCertsCacheTime)
	if request.Header.Get("Nonce") == "" {
		if request.ContentLength == 0 {
			nonce, httpStatus, err := kc.client.GetNonce()
			if err != nil {
				defaultLog.WithError(err).Error("controllers/key_transfer_controller:Transfer() Error retrieving nonce from APS")
				return nil, httpStatus, &commErr.ResourceError{Message: "Error retrieving nonce from APS"}
			}
			responseWriter.Header().Set("Nonce", nonce)
			responseWriter.Header().Set("Attestation-Type", transferPolicy.AttestationType[0])
			return nil, http.StatusNoContent, nil
		} else {
			if request.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
				secLog.Error("controllers/key_transfer_controller:Transfer() Invalid Content-Type")
				return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
			}

			dec := json.NewDecoder(request.Body)
			dec.DisallowUnknownFields()
			err = dec.Decode(&keyTransferRequest)
			if err != nil {
				secLog.WithError(err).Errorf("controllers/key_transfer_controller:Transfer() %s :  Failed to decode JSON request body", commLogMsg.InvalidInputBadEncoding)
				return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to decode JSON request body"}
			}

			tokenClaims, err := kc.authenticateAttestationToken(keyTransferRequest.AttestationToken, cacheTime)
			if err != nil {
				secLog.WithError(err).Errorf("controllers/key_transfer_controller:Transfer() %s :  Failed to authenticate attestation-token", commLogMsg.AuthenticationFailed)
				return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Failed to authenticate attestation-token"}
			}

			if tokenClaims.Tee != transferPolicy.AttestationType[0] {
				secLog.Errorf("controllers/key_transfer_controller:Transfer() attestation-token is not valid for attestation-type in key-transfer policy")
				return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "attestation-token is not valid for attestation-type in key-transfer policy"}
			}

			transferResponse, httpStatus, err := kc.validateClaimsAndGetKey(tokenClaims, transferPolicy, key.KeyInformation.Algorithm, keyTransferRequest.UserData, keyId)
			if err != nil {
				return nil, httpStatus, err
			}
			secLog.WithField("Id", keyId).Infof("controllers/key_transfer_controller:Transfer() %s: Key transferred using Attestation token by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
			return transferResponse, httpStatus, nil
		}
	} else {
		if request.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
			secLog.Error("controllers/key_transfer_controller:Transfer() Invalid Content-Type")
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
		}

		if request.ContentLength == 0 {
			secLog.Error("controllers/key_transfer_controller:Transfer() The request body was not provided")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
		}

		dec := json.NewDecoder(request.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&keyTransferRequest)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/key_transfer_controller: Transfer() %s :  Failed to "+
				"decode JSON request body", commLogMsg.InvalidInputBadEncoding)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to decode JSON request body"}
		}

		if request.Header.Get("Attestation-Type") != transferPolicy.AttestationType[0] {
			secLog.Error("controllers/key_transfer_controller:Transfer() attestation-type in request header does not match with attestation-type in key-transfer policy")
			return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "attestation-type in request header does not match with attestation-type in key-transfer policy"}
		}

		var policyIds []uuid.UUID
		switch transferPolicy.AttestationType[0] {
		case consts.AttestationTypeSGX:
			policyIds = transferPolicy.SGX.PolicyIds

		case consts.AttestationTypeTDX:
			policyIds = transferPolicy.TDX.PolicyIds
		}

		tokenRequest := aps.AttestationTokenRequest{
			Quote:     keyTransferRequest.Quote,
			UserData:  keyTransferRequest.UserData,
			PolicyIds: policyIds,
		}

		token, httpStatus, err := kc.client.GetAttestationToken(request.Header.Get("Nonce"), &tokenRequest)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/key_transfer_controller:Transfer() Error retrieving token from APS")
			return nil, httpStatus, &commErr.ResourceError{Message: "Error retrieving token from APS"}
		}

		tokenClaims, err := kc.authenticateAttestationToken(string(token), cacheTime)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/key_transfer_controller:Transfer() %s :  Failed to authenticate attestation-token", commLogMsg.AuthenticationFailed)
			return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Failed to authenticate attestation-token"}
		}

		transferResponse, httpStatus, err := kc.validateClaimsAndGetKey(tokenClaims, transferPolicy, key.KeyInformation.Algorithm, keyTransferRequest.UserData, keyId)
		if err != nil {
			return nil, httpStatus, err
		}
		secLog.WithField("Id", keyId).Infof("controllers/key_transfer_controller:Transfer() %s: Key transferred using Quote by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
		return transferResponse, httpStatus, nil
	}
}

func (kc *KeyTransferController) authenticateAttestationToken(attestationToken string, cacheTime time.Duration) (*aps.AttestationTokenClaim, error) {
	defaultLog.Trace("controllers/key_transfer_controller:authenticateAttestationToken() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:authenticateAttestationToken() Leaving")

	claims := aps.AttestationTokenClaim{}
	var err error
	var initErr error

	// There are two scenarios when we retry the ValidateTokenAndClaims.
	//     1. The cached verifier has expired - could be because the certificate we are using has just expired
	//        or the time has reached when we want to look at the CRL list to make sure the certificate is still
	//        valid.
	//        Error : VerifierExpiredError
	//     2. There are no valid certificates (maybe all are expired) and we need to call the function that retrieves
	//        a new certificate. initJwtVerifier takes care of this scenario.
	for needInit, retryNeeded, looped := jwtVerifier == nil, false, false; retryNeeded || !looped; looped = true {
		if needInit || retryNeeded {
			if jwtVerifier, initErr = cmw.InitJwtVerifier(kc.keyConfig.ApsJwtSigningCertsDir, kc.keyConfig.TrustedCaCertsDir, cacheTime); initErr != nil {
				return nil, errors.Wrap(initErr, "controllers/key_transfer_controller:authenticateAttestationToken() attempt to initialize jwt verifier failed")
			}
			needInit = false
		}
		retryNeeded = false
		_, err = jwtVerifier.ValidateTokenAndGetClaims(strings.TrimSpace(attestationToken), &claims)
		if err != nil && !looped {
			switch err.(type) {
			case *jwtauth.MatchingCertNotFoundError, *jwtauth.MatchingCertJustExpired:
				err = kc.fnGetApsJwtSigningCerts()
				if err != nil {
					defaultLog.WithError(err).Error("controllers/key_transfer_controller:authenticateAttestationToken() failed to get APS jwt signing certificate")
				}
				retryNeeded = true
			case *jwtauth.VerifierExpiredError:
				retryNeeded = true
			}
		}
	}

	if err != nil {
		// this is an attestation-token validation failure
		secLog.Warningf("controllers/key_transfer_controller:authenticateAttestationToken() %s: Invalid attestation token", commLogMsg.AuthenticationFailed)
		return nil, errors.Wrap(err, "controllers/key_transfer_controller:authenticateAttestationToken() token validation failure")
	}

	return &claims, nil
}

// Fetch JWT Signing certificate from APS
func (kc *KeyTransferController) fnGetApsJwtSigningCerts() error {
	defaultLog.Trace("controllers/key_transfer_controller:fnGetApsJwtSigningCerts() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:fnGetApsJwtSigningCerts() Leaving")

	apsJwtCert, err := kc.client.GetJwtSigningCertificate()
	if err != nil {
		return errors.Wrap(err, "controllers/key_transfer_controller:fnGetApsJwtSigningCerts() Error retrieving JWT signing certificate from APS")
	}
	err = crypt.SavePemCertWithShortSha1FileName(apsJwtCert, kc.keyConfig.ApsJwtSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "controllers/key_transfer_controller:fnGetApsJwtSigningCerts() Could not store JWT signing Certificate")
	}
	return nil
}

func (kc *KeyTransferController) validateClaimsAndGetKey(tokenClaims *aps.AttestationTokenClaim, transferPolicy *kbs.KeyTransferPolicy, keyAlgorithm, userData string, keyId uuid.UUID) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_controller:validateClaimsAndGetKey() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateClaimsAndGetKey() Leaving")

	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/key_transfer_controller:validateClaimsAndGetKey() Failed to validate Token claims against Key transfer Policy attributes")
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Token claims validation against key-policy failed"}
	}

	response, httpStatus, err := kc.getWrappedKey(keyAlgorithm, userData, keyId)
	if err != nil {
		return nil, httpStatus, err
	}
	return response, httpStatus, nil
}

func validateAttestationTokenClaims(tokenClaims *aps.AttestationTokenClaim, transferPolicy *kbs.KeyTransferPolicy) error {
	defaultLog.Trace("controllers/key_transfer_controller:validateAttestationTokenClaims() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateAttestationTokenClaims() Leaving")

	switch transferPolicy.AttestationType[0] {
	case consts.AttestationTypeSGX:
		if tokenClaims.PolicyIds != nil && transferPolicy.SGX.PolicyIds != nil {
			if isPolicyIdMatched(tokenClaims.PolicyIds, transferPolicy.SGX.PolicyIds) {
				return nil
			}
			if transferPolicy.SGX.Attributes == nil {
				return errors.New("controllers/key_transfer_controller:validateAttestationTokenClaims() None of the policy-id in token matched with policy-id in key-transfer policy")
			}
		}
		return validateSGXTokenClaims(tokenClaims, transferPolicy.SGX.Attributes)

	case consts.AttestationTypeTDX:
		if tokenClaims.PolicyIds != nil && transferPolicy.TDX.PolicyIds != nil {
			if isPolicyIdMatched(tokenClaims.PolicyIds, transferPolicy.TDX.PolicyIds) {
				return nil
			}
			if transferPolicy.TDX.Attributes == nil {
				return errors.New("controllers/key_transfer_controller:validateAttestationTokenClaims() None of the policy-id in token matched with policy-id in key-transfer policy")
			}
		}
		return validateTDXTokenClaims(tokenClaims, transferPolicy.TDX.Attributes)

	default:
		return errors.New("controllers/key_transfer_controller:validateAttestationTokenClaims() Unsupported attestation-type")
	}
}

func isPolicyIdMatched(tokenPolicyIds, keyPolicyIds []uuid.UUID) bool {
	for _, tokenPolicyId := range tokenPolicyIds {
		if slice.Contains(keyPolicyIds, tokenPolicyId) {
			return true
		}
	}
	return false
}

func validateSGXTokenClaims(tokenClaims *aps.AttestationTokenClaim, sgxAttributes *kbs.SgxAttributes) error {
	defaultLog.Trace("controllers/key_transfer_controller:validateSGXTokenClaims() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateSGXTokenClaims() Leaving")

	if validateMrSigner(tokenClaims.MrSigner, sgxAttributes.MrSigner) &&
		validateIsvProdId(tokenClaims.IsvProductId, sgxAttributes.IsvProductId) &&
		validateMrEnclave(tokenClaims.MrEnclave, sgxAttributes.MrEnclave) &&
		validateIsvSvn(tokenClaims.IsvSvn, *sgxAttributes.IsvSvn) &&
		validateTcbStatus(tokenClaims.TcbStatus, *sgxAttributes.EnforceTCBUptoDate) {
		defaultLog.Debug("controllers/key_transfer_controller:validateSGXTokenClaims() All sgx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("controllers/key_transfer_controller:validateSGXTokenClaims() sgx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSigner - Function to Validate SignerMeasurement
func validateMrSigner(tokenMrSigner string, policyMrSigner []string) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateMrSigner() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateMrSigner() Leaving")

	if tokenMrSigner == "" {
		defaultLog.Error("controllers/key_transfer_controller:validateMrSigner() MrSigner is missing from attestation token")
		return false
	}

	if slice.Contains(policyMrSigner, tokenMrSigner) {
		defaultLog.Debug("controllers/key_transfer_controller:validateMrSigner() MrSigner in attestation token matches with the key transfer policy")
		return true
	}

	defaultLog.Error("controllers/key_transfer_controller:validateMrSigner() MrSigner in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvProdId - Function to Validate IsvProdId
func validateIsvProdId(tokenIsvProdId uint16, policyIsvProdIds []uint16) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateIsvProdId() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateIsvProdId() Leaving")

	if tokenIsvProdId == 0 {
		defaultLog.Error("controllers/key_transfer_controller:validateIsvProdId() Isv Product Id is missing from attestation token")
		return false
	}

	if slice.Contains(policyIsvProdIds, tokenIsvProdId) {
		defaultLog.Debug("controllers/key_transfer_controller:validateIsvProdId() Isv Product Id in attestation token matches with the key transfer policy")
		return true
	}

	defaultLog.Error("controllers/key_transfer_controller:validateIsvProdId() Isv Product Id in attestation token does not match with the key transfer policy")
	return false
}

// validateMrEnclave - Function to Validate EnclaveMeasurement
func validateMrEnclave(tokenMrEnclave string, policyMrEnclave []string) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateMrEnclave() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateMrEnclave() Leaving")

	if tokenMrEnclave == "" && len(policyMrEnclave) == 0 {
		return true
	}

	if slice.Contains(policyMrEnclave, tokenMrEnclave) {
		defaultLog.Debug("controllers/key_transfer_controller:validateMrEnclave() Enclave Measurement in attestation token matches with the key transfer policy")
		return true
	}

	defaultLog.Error("controllers/key_transfer_controller:validateMrEnclave() Enclave Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvSvn- Function to Validate isvSvn
func validateIsvSvn(tokenIsvSvn uint16, policyIsvSvn uint16) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateIsvSvn() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateIsvSvn() Leaving")

	if tokenIsvSvn == policyIsvSvn {
		defaultLog.Debug("controllers/key_transfer_controller:validateIsvSvn() IsvSvn in attestation token matches with the key transfer policy")
		return true
	}
	defaultLog.Error("controllers/key_transfer_controller:validateIsvSvn() IsvSvn in attestation token does not match with the key transfer policy")
	return false
}

// validateTcbStatus- Function to Validate tcbStatus
func validateTcbStatus(tcbStatus string, enforceTcbUptoDate bool) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateTcbStatus() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateTcbStatus() Leaving")

	if enforceTcbUptoDate && tcbStatus != consts.TCBStatusUpToDate {
		defaultLog.Error("controllers/key_transfer_controller:validateTcbStatus() TCB is not Up-to-Date")
		return false
	}
	return true
}

func validateTDXTokenClaims(tokenClaims *aps.AttestationTokenClaim, tdxAttributes *kbs.TdxAttributes) error {
	defaultLog.Trace("controllers/key_transfer_controller:validateTDXTokenClaims() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateTDXTokenClaims() Leaving")

	if validateMrSignerSeam(tokenClaims.MrSignerSeam, tdxAttributes.MrSignerSeam) &&
		validateMrSeam(tokenClaims.MrSeam, tdxAttributes.MrSeam) &&
		validateSeamSvn(tokenClaims.SeamSvn, *tdxAttributes.SeamSvn) &&
		validateMrTD(tokenClaims.MRTD, tdxAttributes.MRTD) &&
		validateRTMR(tokenClaims.RTMR0, tdxAttributes.RTMR0) &&
		validateRTMR(tokenClaims.RTMR1, tdxAttributes.RTMR1) &&
		validateRTMR(tokenClaims.RTMR2, tdxAttributes.RTMR2) &&
		validateRTMR(tokenClaims.RTMR3, tdxAttributes.RTMR3) &&
		validateTcbStatus(tokenClaims.TcbStatus, *tdxAttributes.EnforceTCBUptoDate) {
		defaultLog.Debug("controllers/key_transfer_controller:validateTDXTokenClaims() All tdx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("controllers/key_transfer_controller:validateTDXTokenClaims() tdx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSignerSeam - Function to Validate MrSignerSeam
func validateMrSignerSeam(tokenMrSignerSeam string, policyMrSignerSeam []string) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateMrSignerSeam() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateMrSignerSeam() Leaving")

	if tokenMrSignerSeam == "" {
		defaultLog.Error("controllers/key_transfer_controller:validateMrSignerSeam() MrSignerSeam is missing from attestation token")
		return false
	}

	if slice.Contains(policyMrSignerSeam, tokenMrSignerSeam) {
		defaultLog.Debug("controllers/key_transfer_controller:validateMrSignerSeam() MrSignerSeam in attestation token matches with the key transfer policy")
		return true
	}

	defaultLog.Error("controllers/key_transfer_controller:validateMrSignerSeam() MrSignerSeam in attestation token does not match with the key transfer policy")
	return false
}

// validateMrSeam - Function to Validate SeamMeasurement
func validateMrSeam(tokenMrSeam string, policyMrSeam []string) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateMrSeam() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateMrSeam() Leaving")

	if tokenMrSeam == "" {
		defaultLog.Error("controllers/key_transfer_controller:validateMrSeam() Seam Measurement is missing from attestation token")
		return false
	}

	if slice.Contains(policyMrSeam, tokenMrSeam) {
		defaultLog.Debug("controllers/key_transfer_controller:validateMrSeam() Seam Measurement in attestation token matches with the key transfer policy")
		return true
	}

	defaultLog.Error("controllers/key_transfer_controller:validateMrSeam() Seam Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateSeamSvn- Function to Validate seamSvn
func validateSeamSvn(tokenSeamSvn uint8, policySeamSvn uint8) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateSeamSvn() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateSeamSvn() Leaving")

	if tokenSeamSvn == policySeamSvn {
		defaultLog.Debug("controllers/key_transfer_controller:validateSeamSvn() Seam Svn in attestation token matches with the key transfer policy")
		return true
	}
	defaultLog.Error("controllers/key_transfer_controller:validateSeamSvn() Seam Svn in attestation token does not match with the key transfer policy")
	return false
}

// validateMrTD - Function to Validate TDMeasurement
func validateMrTD(tokenMrTD string, policyMrTD []string) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateMrTD() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateMrTD() Leaving")

	if tokenMrTD == "" && len(policyMrTD) == 0 {
		return true
	}

	if slice.Contains(policyMrTD, tokenMrTD) {
		defaultLog.Debug("controllers/key_transfer_controller:validateMrTD() TD Measurement in attestation token matches with the key transfer policy")
		return true
	}

	defaultLog.Error("controllers/key_transfer_controller:validateMrTD() TD Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateRTMR - Function to Validate RTMR
func validateRTMR(tokenRTMR string, policyRTMR string) bool {
	defaultLog.Trace("controllers/key_transfer_controller:validateRTMR() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:validateRTMR() Leaving")

	if tokenRTMR == "" && policyRTMR == "" {
		return true
	}

	if tokenRTMR == policyRTMR {
		defaultLog.Debug("controllers/key_transfer_controller:validateRTMR() RTMR in attestation token matches with the key transfer policy")
		return true
	}

	defaultLog.Error("controllers/key_transfer_controller:validateRTMR() RTMR in attestation token does not match with the key transfer policy")
	return false
}

func (kc *KeyTransferController) getWrappedKey(keyAlgorithm, userData string, id uuid.UUID) (interface{}, int, error) {
	defaultLog.Trace("controllers/key_transfer_controller:getWrappedKey() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:getWrappedKey() Leaving")

	publicKey, err := getPublicKey(userData)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/key_transfer_controller:getWrappedKey() Error in getting public key")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in getting public key"}
	}

	secretKey, status, err := getSecretKey(kc.remoteManager, id)
	if err != nil {
		return nil, status, err
	}

	if keyAlgorithm == consts.CRYPTOALG_RSA {
		swk, err := CreateSwk()
		if err != nil {
			secLog.Error("controllers/key_transfer_controller:getWrappedKey() Error in creating SWK key")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error in creating SWK key"}
		}

		privatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: secretKey.([]byte),
			},
		)

		decodedBlock, _ := pem.Decode(privatePem)
		if decodedBlock == nil {
			defaultLog.Error("controllers/key_transfer_controller:getWrappedKey() Failed to decode secret key")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to decode secret key"}
		}
		// Wrap secret key with swk
		bytes, nonceByte, err := AesEncrypt(decodedBlock.Bytes, swk)
		if err != nil {
			defaultLog.Error("controllers/key_transfer_controller:getWrappedKey() Failed to encrypt secret key with swk")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to encrypt secret key with swk"}
		}

		keyMetaDataSize := ivSize + tagSize + wrapSize
		ivLength := len(nonceByte)
		keyMetaData := make([]byte, keyMetaDataSize)
		binary.LittleEndian.PutUint32(keyMetaData[0:], uint32(ivLength))
		binary.LittleEndian.PutUint32(keyMetaData[4:], uint32(16))
		binary.LittleEndian.PutUint32(keyMetaData[8:], uint32(len(bytes)))

		wrappedKey := []byte{}
		wrappedKey = append(wrappedKey, keyMetaData...)
		wrappedKey = append(wrappedKey, nonceByte...)
		wrappedKey = append(wrappedKey, bytes...)

		// Wrap SWK with public key
		wrappedSWK, status, err := wrapKey(publicKey, swk, sha512.New384(), nil)
		if err != nil {
			return nil, status, err
		}
		transferResponse := kbs.KeyTransferResponse{
			WrappedKey: base64.StdEncoding.EncodeToString(wrappedKey),
			WrappedSWK: base64.StdEncoding.EncodeToString(wrappedSWK.([]byte)),
		}
		return transferResponse, http.StatusOK, nil
	}

	// Wrap secret key with public key
	wrappedKey, status, err := wrapKey(publicKey, secretKey.([]byte), sha512.New384(), nil)
	if err != nil {
		return nil, status, err
	}

	transferResponse := kbs.KeyTransferResponse{
		WrappedKey: base64.StdEncoding.EncodeToString(wrappedKey.([]byte)),
	}
	return transferResponse, http.StatusOK, nil
}

func getPublicKey(userData string) (*rsa.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(userData)
	if err != nil {
		return nil, errors.New("failed to decode user data")
	}

	n := big.Int{}
	n.SetBytes(key[4:])
	eb := binary.LittleEndian.Uint32(key[:])
	pubKey := rsa.PublicKey{N: &n, E: int(eb)}

	return &pubKey, nil
}

// CreateSwk - Function to create swk
func CreateSwk() ([]byte, error) {
	defaultLog.Trace("controllers/key_transfer_controller:CreateSwk() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:CreateSwk() Leaving")

	// create an AES Key here of 256 bits
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/key_transfer_controller:CreateSwk() Failed to generate random key bytes")
	}

	return keyBytes, nil
}

// AesEncrypt encrypts plain bytes using AES key passed as param
func AesEncrypt(data, key []byte) ([]byte, []byte, error) {
	defaultLog.Trace("controllers/key_transfer_controller:AesEncrypt() Entering")
	defer defaultLog.Trace("controllers/key_transfer_controller:AesEncrypt() Leaving")

	// generate a new aes cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal

	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// here we encrypt data using the Seal function
	return gcm.Seal(nil, nonce, data, nil), nonce, nil
}
