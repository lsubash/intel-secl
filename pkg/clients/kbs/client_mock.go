/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/stretchr/testify/mock"
)

type MockKbsClient struct {
	mock.Mock
}

func NewMockKBSClient() KBSClient {
	mockKbsClient := &MockKbsClient{}
	return mockKbsClient
}

// CreateKey sends a POST to /keys to create a new Key with specified parameters
func (k *MockKbsClient) CreateKey(keyRequest *kbs.KeyRequest) (*kbs.KeyResponse, error) {
	args := k.Called(keyRequest)
	return args.Get(0).(*kbs.KeyResponse), args.Error(1)
}

// GetKey performs a POST to /keys/{id} to retrieve the actual key data from the KBS
func (k *MockKbsClient) GetKey(keyId, pubKey string) (*kbs.KeyTransferResponse, error) {
	args := k.Called(keyId, pubKey)
	return args.Get(0).(*kbs.KeyTransferResponse), args.Error(1)
}

// TransferKey performs a POST to /keys/{key_id}/transfer to retrieve the challenge data from the KBS
func (k *MockKbsClient) TransferKey(keyId string) (string, string, error) {
	args := k.Called(keyId)
	return args.Get(0).(string), args.Get(1).(string), args.Error(2)
}

// TransferKeyWithSaml performs a POST to /keys/{id}/transfer to retrieve the actual key data from the KBS
func (k *MockKbsClient) TransferKeyWithSaml(keyId, saml string) ([]byte, error) {
	args := k.Called(keyId, saml)
	return args.Get(0).([]byte), args.Error(1)
}

// TransferKeyWithEvidence performs a POST to /keys/{key_id}/transfer to retrieve the actual key data from the KBS
func (k *MockKbsClient) TransferKeyWithEvidence(keyId, nonce, attestationType string, request *kbs.KeyTransferRequest) (*kbs.KeyTransferResponse, error) {
	args := k.Called(keyId, nonce, attestationType, request)
	return args.Get(0).(*kbs.KeyTransferResponse), args.Error(1)
}
