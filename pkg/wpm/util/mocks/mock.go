/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"io/ioutil"
	"time"

	"github.com/google/uuid"
	kbsc "github.com/intel-secl/intel-secl/v5/pkg/clients/kbs"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

const testPublicKey = "../../../test/wpm/" + "publickey.pub"

func MockCreateKey(baseURL string, kbsClient *kbsc.MockKbsClient) {
	key := make([]byte, 32)
	rand.Read(key)
	keyID := uuid.New()
	// Parse response
	keyResponse := kbs.KeyResponse{
		KeyInformation: &kbs.KeyInformation{
			ID:        keyID,
			Algorithm: "AES",
			KeyLength: 256,
			KeyString: base64.StdEncoding.EncodeToString(key),
		},
		TransferPolicyID: uuid.New(),
		TransferLink:     baseURL + keyID.String() + "/transfer/",
		CreatedAt:        time.Now(),
		Label:            "test-Key",
		Usage:            "unit-testing",
	}
	kbsClient.On("CreateKey", mock.Anything).Return(&keyResponse, nil)
}

const (
	validKeyIDWithResponse = "f38c2baf-a02f-4110-bdea-29e076113013"
)

func MockGetKey(keyId string, kbsClient *kbsc.MockKbsClient) {

	var key kbs.KeyTransferResponse

	pubKey, _ := ioutil.ReadFile(testPublicKey)

	if pubKey == nil || keyId == "" {
		kbsClient.On("GetKey", mock.Anything).Return(&key, errors.New("Failed to perform GetKey operation"))
	}
	// Decode public key in request
	pubKeyBytes, err := crypt.GetPublicKeyFromPem(pubKey)
	if err != nil {
		kbsClient.On("GetKey", mock.Anything).Return(&key, errors.New("Failed to load publickey"))
	}
	envelopeKey := pubKeyBytes.(*rsa.PublicKey)

	var keys []kbs.KeyResponse

	// Valid Key and KeyResponse
	if keyId == validKeyIDWithResponse {
		aesKey := make([]byte, 32)
		_, err := rand.Read(aesKey)
		if err != nil {
			kbsClient.On("GetKey", mock.Anything).Return(&key, errors.New("Failed to create key"))
		}
		keyResponse := kbs.KeyResponse{
			KeyInformation: &kbs.KeyInformation{
				ID:        uuid.MustParse(validKeyIDWithResponse),
				Algorithm: "AES",
				KeyLength: 256,
				KeyString: base64.StdEncoding.EncodeToString(aesKey),
			},
			TransferPolicyID: uuid.New(),
			CreatedAt:        time.Now(),
			Label:            "test-Key",
			Usage:            "unit-testing",
		}
		keys = append(keys, keyResponse)
	}
	for _, keyResponse := range keys {
		if keyResponse.KeyInformation.ID == uuid.MustParse(keyId) {
			decodedKey, _ := base64.StdEncoding.DecodeString(keyResponse.KeyInformation.KeyString)
			// Wrap secret key with public key
			wrappedKey, err := rsa.EncryptOAEP(sha512.New384(), rand.Reader, envelopeKey, decodedKey, nil)
			if err != nil {
				kbsClient.On("GetKey", mock.Anything).Return(&key, errors.Wrap(err, "Wrap key failed"))
			}
			key.WrappedKey = base64.StdEncoding.EncodeToString(wrappedKey)
		}
	}

	kbsClient.On("GetKey", mock.Anything, mock.Anything).Return(&key, nil)
}
