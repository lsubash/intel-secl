/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/tpmprovider"
	taModel "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func mockTpmProvider(mockedTpmProvider *tpmprovider.MockedTpmProvider) {
	tpmSecretKey := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	var quoteBytes = []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	var keyBytes = []byte("1234567890123456")

	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("CreateEk", tpmSecretKey, mock.Anything).Return(nil)
	mockedTpmProvider.On("CreateAik", tpmSecretKey).Return(nil)
	mockedTpmProvider.On("IsValidEk", tpmSecretKey, mock.Anything, mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider.On("GetAikBytes").Return(quoteBytes, nil)
	mockedTpmProvider.On("GetAikName").Return([]byte("TestAikName"), nil)
	mockedTpmProvider.On("ActivateCredential", tpmSecretKey, mock.Anything, mock.Anything).Return(keyBytes, nil)

}

func mockPrivacyCaClient(t *testing.T, mockedPrivacyCaClient *hvsclient.MockedPrivacyCAClient) {

	var SHORT_BYTES = 2
	var keyBytes = []byte("1234567890123456")

	credentialBlob := new(bytes.Buffer)
	err := binary.Write(credentialBlob, binary.BigEndian, int16(SHORT_BYTES))
	if err != nil {
		assert.NoError(t, err)
	}

	secretsBlob := new(bytes.Buffer)
	err = binary.Write(secretsBlob, binary.BigEndian, int16(SHORT_BYTES))
	if err != nil {
		assert.NoError(t, err)
	}

	mockedPrivacyCaClient.On("DownloadPrivacyCa", mock.Anything).Return([]uint8{}, nil)
	mockedPrivacyCaClient.On("GetIdentityProofRequest", mock.Anything).Return(&taModel.IdentityProofRequest{Credential: credentialBlob.Bytes(), Secret: secretsBlob.Bytes(), SymmetricBlob: keyBytes, TpmSymmetricKeyParams: taModel.TpmSymmetricKeyParams{IV: keyBytes}}, nil)
	mockedPrivacyCaClient.On("GetIdentityProofResponse", mock.Anything).Return(&taModel.IdentityProofRequest{Credential: credentialBlob.Bytes(), Secret: secretsBlob.Bytes(), SymmetricBlob: keyBytes, TpmSymmetricKeyParams: taModel.TpmSymmetricKeyParams{IV: keyBytes}}, nil)
}
