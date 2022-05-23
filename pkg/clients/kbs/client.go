/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
)

const (
	wrappedKeyID           = "03830633-500f-438a-bf31-d87e54da1af9"
	invalidWrappedKeyID    = "5c2cc23f-4697-47fd-b0ef-10fee512e489"
	validKeyIDWithResponse = "f38c2baf-a02f-4110-bdea-29e076113013"
)

var log = commLog.GetDefaultLogger()

type KBSClient interface {
	CreateKey(*kbs.KeyRequest) (*kbs.KeyResponse, error)
	GetKey(string, string) (*kbs.KeyTransferResponse, error)
	TransferKey(string) (string, string, error)
	TransferKeyWithSaml(string, string) ([]byte, error)
	TransferKeyWithEvidence(string, string, string, *kbs.KeyTransferRequest) (*kbs.KeyTransferResponse, error)
}

func NewKBSClient(aasURL, kbsURL *url.URL, username, password, token string, certs []x509.Certificate) KBSClient {
	return &kbsClient{
		AasURL:   aasURL,
		BaseURL:  kbsURL,
		UserName: username,
		Password: password,
		JwtToken: token,
		CaCerts:  certs,
	}
}

type kbsClient struct {
	AasURL   *url.URL
	BaseURL  *url.URL
	UserName string
	Password string
	JwtToken string
	CaCerts  []x509.Certificate
}

type mockKbsClient struct {
	AasURL   *url.URL
	BaseURL  *url.URL
	UserName string
	Password string
	JwtToken string
	CaCerts  []x509.Certificate
	keys     []kbs.KeyResponse
}

func NewMockKBSClient(aasURL, kbsURL *url.URL, username, password, token string, certs []x509.Certificate) KBSClient {
	return &mockKbsClient{
		AasURL:   aasURL,
		BaseURL:  kbsURL,
		UserName: username,
		Password: password,
		JwtToken: token,
		CaCerts:  certs,
	}
}

// CreateKey sends a POST to /keys to create a new Key with specified parameters
func (k *mockKbsClient) CreateKey(keyRequest *kbs.KeyRequest) (*kbs.KeyResponse, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("Failed to create key")
	}
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
		TransferLink:     k.BaseURL.String() + keyID.String() + "/transfer/",
		CreatedAt:        time.Now(),
		Label:            "test-Key",
		Usage:            "unit-testing",
	}

	k.keys = append(k.keys, keyResponse)
	return &keyResponse, nil
}

// GetKey performs a POST to /keys/{id} to retrieve the actual key data from the KBS
func (k *mockKbsClient) GetKey(keyId, pubKey string) (*kbs.KeyTransferResponse, error) {
	var key kbs.KeyTransferResponse

	if pubKey == "" || keyId == "" {
		return nil, errors.New("Failed to perform GetKey operation")
	}
	// Decode public key in request
	pubKeyBytes, err := crypt.GetPublicKeyFromPem([]byte(pubKey))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load publickey")
	}
	envelopeKey := pubKeyBytes.(*rsa.PublicKey)

	// Invalid length of WrappedKey
	if keyId == invalidWrappedKeyID {
		key.WrappedKey = "hVmYq3t6w9z$C&F)J@NcRfTjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E(H+Mb"
		return &key, nil
	}

	// Generate only wrappedkey and add it in 'key'
	if keyId == wrappedKeyID {
		aesKey := make([]byte, 16)
		_, err := rand.Read(aesKey)
		if err != nil {
			return nil, errors.New("Failed to create key")
		}
		wrappedKey, err := rsa.EncryptOAEP(sha512.New384(), rand.Reader, envelopeKey, aesKey, nil)
		if err != nil {
			return nil, errors.Wrap(err, "Wrap key failed")
		}
		key.WrappedKey = base64.StdEncoding.EncodeToString(wrappedKey)
	}

	// Valid Key and KeyResponse
	if keyId == validKeyIDWithResponse {
		aesKey := make([]byte, 32)
		_, err := rand.Read(aesKey)
		if err != nil {
			return nil, errors.New("Failed to create key")
		}
		keyResponse := kbs.KeyResponse{
			KeyInformation: &kbs.KeyInformation{
				ID:        uuid.MustParse(validKeyIDWithResponse),
				Algorithm: "AES",
				KeyLength: 256,
				KeyString: base64.StdEncoding.EncodeToString(aesKey),
			},
			TransferPolicyID: uuid.New(),
			TransferLink:     k.BaseURL.String() + keyId + "/transfer/",
			CreatedAt:        time.Now(),
			Label:            "test-Key",
			Usage:            "unit-testing",
		}
		k.keys = append(k.keys, keyResponse)
	}
	for _, keyResponse := range k.keys {
		if keyResponse.KeyInformation.ID == uuid.MustParse(keyId) {
			decodedKey, _ := base64.StdEncoding.DecodeString(keyResponse.KeyInformation.KeyString)
			// Wrap secret key with public key
			wrappedKey, err := rsa.EncryptOAEP(sha512.New384(), rand.Reader, envelopeKey, decodedKey, nil)
			if err != nil {
				return nil, errors.Wrap(err, "Wrap key failed")
			}
			key.WrappedKey = base64.StdEncoding.EncodeToString(wrappedKey)
		}
	}

	return &key, nil
}

// TransferKey performs a POST to /keys/{key_id}/transfer to retrieve the challenge data from the KBS
func (k *mockKbsClient) TransferKey(keyId string) (string, string, error) {
	return "", "", nil
}

// TransferKeyWithSaml performs a POST to /keys/{id}/transfer to retrieve the actual key data from the KBS
func (k *mockKbsClient) TransferKeyWithSaml(keyId, saml string) ([]byte, error) {
	return nil, nil
}

// TransferKeyWithEvidence performs a POST to /keys/{key_id}/transfer to retrieve the actual key data from the KBS
func (k *mockKbsClient) TransferKeyWithEvidence(keyId, nonce, attestationType string, request *kbs.KeyTransferRequest) (*kbs.KeyTransferResponse, error) {
	return nil, nil
}
