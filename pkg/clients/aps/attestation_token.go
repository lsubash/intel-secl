/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aps

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/util"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aps"
	"github.com/pkg/errors"
)

// GetNonce sends a POST to /attestation-token to create a new Nonce to be used as userdata for quote generation
func (a *apsClient) GetNonce() (string, error) {
	defaultLog.Trace("aps/attestation_token:GetNonce() Entering")
	defer defaultLog.Trace("aps/attestation_token:GetNonce() Leaving")

	tokenURL, _ := url.Parse("attestation-token")
	reqURL := a.BaseURL.ResolveReference(tokenURL)
	req, err := http.NewRequest("POST", reqURL.String(), nil)
	if err != nil {
		return "", errors.Wrap(err, "aps/attestation_token:GetNonce() Error initializing http request")
	}

	// Set the request headers
	req.Header.Set("Authorization", "Bearer "+a.JwtToken)
	rsp, err := util.GetHTTPResponse(req, a.CaCerts, false)
	if err != nil {
		return "", errors.Wrap(err, "aps/attestation_token:GetNonce() Error response received from APS")
	}
	defer func() {
		derr := rsp.Body.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("aps/attestation_token:GetNonce() Error closing response body")
		}
	}()

	// Parse response headers
	nonce := rsp.Header.Get("Nonce")
	return nonce, nil
}

// GetAttestationToken sends a POST to /attestation-token to create a new Attestation token with the specified quote attributes
func (a *apsClient) GetAttestationToken(nonce string, tokenRequest *aps.AttestationTokenRequest) ([]byte, error) {
	defaultLog.Trace("aps/attestation_token:GetAttestationToken() Entering")
	defer defaultLog.Trace("aps/attestation_token:GetAttestationToken() Leaving")

	reqBytes, err := json.Marshal(tokenRequest)
	if err != nil {
		return nil, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Error marshalling attestation token request")
	}

	tokenURL, _ := url.Parse("attestation-token")
	reqURL := a.BaseURL.ResolveReference(tokenURL)
	req, err := http.NewRequest("POST", reqURL.String(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Error initializing http request")
	}

	// Set the request headers
	req.Header.Set("Accept", constants.HTTPMediaTypeJwt)
	req.Header.Set("Authorization", "Bearer "+a.JwtToken)
	req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
	req.Header.Set("Nonce", nonce)
	rsp, err := util.SendNoAuthRequest(req, a.CaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Error response received from APS")
	}

	return rsp, nil
}
