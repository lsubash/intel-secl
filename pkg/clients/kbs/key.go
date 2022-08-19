/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/util"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
)

// CreateKey sends a POST to /keys to create a new Key with specified parameters
func (k *kbsClient) CreateKey(keyRequest *kbs.KeyRequest) (*kbs.KeyResponse, error) {
	log.Trace("kbs/client:CreateKey() Entering")
	defer log.Trace("kbs/client:CreateKey() Leaving")

	reqBytes, err := json.Marshal(keyRequest)
	if err != nil {
		return nil, errors.Wrap(err, "Error marshalling key creation request")
	}

	keysURL, _ := url.Parse("keys")
	reqURL := k.BaseURL.ResolveReference(keysURL)
	req, err := http.NewRequest(http.MethodPost, reqURL.String(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, errors.Wrap(err, "Error initializing key creation request")
	}

	// Set the request headers
	req.Header.Set("Accept", constants.HTTPMediaTypeJson)
	req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
	rsp, err := util.SendRequest(req, k.AasURL.String(), k.UserName, k.Password, k.CaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "Error response from key creation request")
	}

	// Parse response
	var keyResponse kbs.KeyResponse
	err = json.Unmarshal(rsp, &keyResponse)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshalling key creation response")
	}

	return &keyResponse, nil
}

// GetKey performs a POST to /keys/{id} to retrieve the actual key data from the KBS
func (k *kbsClient) GetKey(keyId, pubKey string) (*kbs.KeyTransferResponse, error) {
	log.Trace("kbs/client:TransferKey() Entering")
	defer log.Trace("kbs/client:TransferKey() Leaving")

	keyURL, _ := url.Parse("keys/" + keyId)
	reqURL := k.BaseURL.ResolveReference(keyURL)
	req, err := http.NewRequest("POST", reqURL.String(), strings.NewReader(pubKey))
	if err != nil {
		return nil, errors.Wrap(err, "Error initializing key retrieval request")
	}

	// Set the request headers
	req.Header.Set("Accept", constants.HTTPMediaTypeJson)
	req.Header.Set("Content-Type", constants.HTTPMediaTypePlain)
	rsp, err := util.SendRequest(req, k.AasURL.String(), k.UserName, k.Password, k.CaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "Error response from key retrieval request")
	}

	// Parse response
	var key kbs.KeyTransferResponse
	err = json.Unmarshal(rsp, &key)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshalling key retrieval response")
	}

	return &key, nil
}

// TransferKeyWithSaml performs a POST to /keys/{id}/transfer to retrieve the actual key data from the KBS
func (k *kbsClient) TransferKeyWithSaml(keyId, saml string) ([]byte, error) {
	log.Trace("kbs/client:TransferKeyWithSaml() Entering")
	defer log.Trace("kbs/client:TransferKeyWithSaml() Leaving")

	keyURL, _ := url.Parse("keys/" + keyId + "/transfer")
	reqURL := k.BaseURL.ResolveReference(keyURL)
	req, err := http.NewRequest("POST", reqURL.String(), strings.NewReader(saml))
	if err != nil {
		return nil, errors.Wrap(err, "Error initializing key transfer request")
	}

	// Set the request headers
	req.Header.Set("Accept", constants.HTTPMediaTypeOctetStream)
	req.Header.Set("Content-Type", constants.HTTPMediaTypeSaml)
	rsp, err := util.SendNoAuthRequest(req, k.CaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "Error response from key transfer request")
	}

	return rsp, nil
}
