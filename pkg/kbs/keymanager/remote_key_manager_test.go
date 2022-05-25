/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"testing"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/mocks"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/kmipclient"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/stretchr/testify/mock"
)

func TestRemoteManager_CreateKey(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	url, _ := uuid.Parse("fc0cc779-22b6-4741-b0d9-e2e69635ad1e")
	policyId, _ := uuid.Parse("3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9")

	keyStore = mocks.NewFakeKeyStore()
	type fields struct {
		store       domain.KeyStore
		manager     KeyManager
		endpointURL string
	}
	type args struct {
		request *kbs.KeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *kbs.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate create key with valid input, should create a new key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				request: &kbs.KeyRequest{
					KeyInformation: &kbs.KeyInformation{
						ID:        url,
						Algorithm: "AES",
						KeyLength: 256,
					},
					TransferPolicyID: policyId,
				},
			},
			wantErr: false,
		},
		{
			name: "Validate create key with empty endpointurl, should fail to create new key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: "",
			},
			args: args{
				request: &kbs.KeyRequest{
					KeyInformation:   &kbs.KeyInformation{},
					TransferPolicyID: policyId,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:       tt.fields.store,
				manager:     tt.fields.manager,
				endpointURL: tt.fields.endpointURL,
			}
			_, err := rm.CreateKey(tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManager_RetrieveKey(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store       domain.KeyStore
		manager     KeyManager
		endpointURL string
	}
	type args struct {
		keyId uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *kbs.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate retrieve key with valid input, should retrieve a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: false,
		},
		{
			name: "Validate retrieve key with invalid keyid, should fail to retrieve a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e3"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:       tt.fields.store,
				manager:     tt.fields.manager,
				endpointURL: tt.fields.endpointURL,
			}

			_, err := rm.RetrieveKey(tt.args.keyId)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.RetrieveKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManager_DeleteKey(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	keyStore = mocks.NewFakeKeyStore()
	type fields struct {
		store       domain.KeyStore
		manager     KeyManager
		endpointURL string
	}
	type args struct {
		keyId uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Validate delete key with valid input, should delete a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: false,
		},
		{
			name: "Validate delete key with empty endpointurl, should fail to delete a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: "",
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: true,
		},
		{
			name: "Validate delete key with invalid keyid, should fail to delete a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce9a3"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:       tt.fields.store,
				manager:     tt.fields.manager,
				endpointURL: tt.fields.endpointURL,
			}
			if err := rm.DeleteKey(tt.args.keyId); (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoteManager_SearchKeys(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store       domain.KeyStore
		manager     KeyManager
		endpointURL string
	}
	type args struct {
		criteria *models.KeyFilterCriteria
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*kbs.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate search key with valid input, should search for a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				criteria: &models.KeyFilterCriteria{
					Algorithm:        "AES",
					KeyLength:        256,
					TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:       tt.fields.store,
				manager:     tt.fields.manager,
				endpointURL: tt.fields.endpointURL,
			}
			_, err := rm.SearchKeys(tt.args.criteria)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.SearchKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManager_RegisterKey(t *testing.T) {

	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store       domain.KeyStore
		manager     KeyManager
		endpointURL string
	}
	type args struct {
		request *kbs.KeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *kbs.KeyResponse
		wantErr bool
	}{
		{
			name: "Validate register key with valid input, should register a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				request: &kbs.KeyRequest{
					KeyInformation: &kbs.KeyInformation{
						ID:        uuid.MustParse("fc0cc779-22b6-4741-b0d9-e2e69635ad1e"),
						Algorithm: "AES",
						KeyLength: 256,
						KmipKeyID: "1",
					},
					TransferPolicyID: uuid.MustParse("3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9"),
				},
			},
			wantErr: false,
		},
		{
			name: "Validate register key with empty endpointurl, should fail to register a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: "",
			},
			args: args{
				request: &kbs.KeyRequest{
					KeyInformation:   &kbs.KeyInformation{},
					TransferPolicyID: uuid.MustParse("3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9"),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:       tt.fields.store,
				manager:     tt.fields.manager,
				endpointURL: tt.fields.endpointURL,
			}
			_, err := rm.RegisterKey(tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.RegisterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRemoteManager_TransferKey(t *testing.T) {

	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	keyStore = mocks.NewFakeKeyStore()

	type fields struct {
		store       domain.KeyStore
		manager     KeyManager
		endpointURL string
	}
	type args struct {
		keyId uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate transfer key with valid input, should transfer a key",
			fields: fields{
				store:       keyStore,
				manager:     keyManager,
				endpointURL: endpointUrl,
			},
			args: args{
				keyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: false,
		},
		{
			name: "Validate transfer key with invalid input, should fail to transfer a key",
			fields: fields{
				store:       keyStore,
				manager:     nil,
				endpointURL: "",
			},
			args: args{
				keyId: uuid.Nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RemoteManager{
				store:       tt.fields.store,
				manager:     tt.fields.manager,
				endpointURL: tt.fields.endpointURL,
			}
			_, err := rm.TransferKey(tt.args.keyId)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteManager.TransferKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewRemoteManager(t *testing.T) {
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	keyStore = mocks.NewFakeKeyStore()

	type args struct {
		ks  domain.KeyStore
		km  KeyManager
		url string
	}
	tests := []struct {
		name string
		args args
		want *RemoteManager
	}{
		{
			name: "Validate passing input to the struct, should fill without any error",
			args: args{
				ks:  keyStore,
				km:  keyManager,
				url: endpointUrl,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewRemoteManager(tt.args.ks, tt.args.km, tt.args.url)
		})
	}
}
