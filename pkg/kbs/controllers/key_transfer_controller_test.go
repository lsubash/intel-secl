/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"log"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	aasClient "github.com/intel-secl/intel-secl/v5/pkg/clients/aas"
	apsClient "github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/stretchr/testify/mock"

	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/mocks"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/kmipclient"
)

const (
	APSURL    = "https://aps.com:5443/aps/v1/"
	JwtToken  = "test_token"
	CmsRootCa = "MIIELDCCApSgAwIBAgIBADANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UEAxMFQ01TQ0EwHhcNMjIwMTA0MDkzMTMwWhcNMjcwMTA0MDkzMTMwWjBHMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UEAxMFQ01TQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfrDvpjCTgS7qdFom5xyrg80eqsT3CCtSSx7W33XJ6Y4ELDjP3L238XieEvwrQjB1l8ReHC4RspWf7Mhlu5oUioc9dWHErwLy6AdokJnnKZNCcgHTz2rRAIahFbT9iRRTAg6/B5Ya+9s9SSLZcWNe7caXAhQeABssrjZSNrh1aYj9GSq8bnExO1AVNJzFBBnYn5OzjWecvaaysMNel624wHcwRyq33u+dBITuYSeE1kXG3mTWG/gxXrW89ONuLpxAn12iWsZtJ2USzcg8dURTHNoqI63dnr3jCW9OFfFchAuFkQnIzI3PV2MI30Ku2Me6ZCk6F+1HunChbqwaGlZ/klCOgiHZCtTBqKJfqXC7BftGjynwtPTNh/HIGfWMSaPF+kxcHkpnBwNC4ZkMnhgn62GK2WKPJwGTYZ8iFZ4X3duRowZA/uMK/LiYzBpI0MRg/OgQn4vcm+FIh4CiOCcwK3QT3c83MMbRq7CdRz4cXVwD/uh7mEC6YettvqCqXSQMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggGBABNWn4uDanR6uYnydUNguMEBYf5Up381RC+lwIAv51aDhMx7/mPcApBJWTIjpOTMorDUiGiXUnKkPoKx3ulNPeq+QCoAaZgvsZzK8wixuTTPDBJ2yOs34zBoRNzPFptDbf4drXZq8UeIwDFo5LVCMONFxE/wDaDfc2f/XKIJghHf6dDZZG9mCgIDpWRy/CrkHg4GYomW81QSI/rIyorMPUIHG8ydh/vpM5T7jJKaDq5fNc67ePxFo5WuNUFA+QO+0VAfpvQwYmjrD/BfxJ62Abwc7oZoFJ+iutwoe1Cap5IN7vorZ5C8idqcKnln8k6bLbFb+Ud7F9GNJwP/mSgf/rYIO+T0ovVRmyF8XFCaD3TIyT28MCsNDn0eanEveg1JHZcsh9HaryWIuFG4cQJnLRoKRROkLtpElmrwk7zvG8yM6Eus7PGyGcnSuEH/Zs8NdGxcuLCkB3IBESG/CXP261e1HpBvSOg3lxdojOvBZsHeQHStcmFJXIXV2gWVeM+Ocg=="
)

func TestKeyTransferController_authenticateToken(t *testing.T) {
	apsURL, err := url.Parse(APSURL)
	if err != nil {
		log.Fatal("Error parsing APS url")
	}

	var caCerts []x509.Certificate
	cmsCA, err := base64.StdEncoding.DecodeString(CmsRootCa)
	if err != nil {
		log.Fatal("Error in decoding cert")
	}

	cert, err := x509.ParseCertificate(cmsCA)
	if err != nil {
		log.Fatal("Error in parcing cert")
	}

	caCerts = append(caCerts, *cert)

	mockAps := NewMockApsClient(apsURL, caCerts, JwtToken)

	type fields struct {
		remoteManager *keymanager.RemoteManager
		policyStore   domain.KeyTransferPolicyStore
		keyConfig     domain.KeyTransferControllerConfig
		apsClient     apsClient.APSClient
		aasClient     *aasClient.Client
	}
	type args struct {
		token            string
		cacheTime        time.Duration
		attestationToken bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    interface{}
		wantErr bool
	}{
		{
			name: "Validate authenticate token with invalid token, should fail to authenticate",
			fields: fields{
				keyConfig: domain.KeyTransferControllerConfig{
					AasBaseUrl: "https://aas.com:5443/aas/v1/",
				},
				apsClient: mockAps,
			},
			args: args{
				token:            "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ",
				cacheTime:        time.Second,
				attestationToken: true,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := &KeyTransferController{
				remoteManager: tt.fields.remoteManager,
				policyStore:   tt.fields.policyStore,
				keyConfig:     tt.fields.keyConfig,
				apsClient:     tt.fields.apsClient,
				aasClient:     tt.fields.aasClient,
			}

			got, err := kc.authenticateToken(tt.args.token, tt.args.cacheTime, tt.args.attestationToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyTransferController.authenticateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyTransferController.authenticateToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyTransferController_validateClaimsAndGetKey(t *testing.T) {
	var i uint16 = 0
	var j uint8 = 0
	var k uint8 = 1
	var l uint16 = 1
	var pid uint16 = 1
	var keyStore *mocks.MockKeyStore

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := keymanager.NewKmipManager(mockClient)

	endpointUrl := "https://localhost:9443/kbs/v1"

	keyStore = mocks.NewFakeKeyStore()
	remote_manager := keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)

	//Envelope key
	keyPair, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &keyPair.PublicKey
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	var publicKeyInPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	pub := pem.EncodeToMemory(publicKeyInPem)

	loadedPubKey, _ := loadPublicKey(pub)

	sgxUrl1, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5bf")
	sgxUrl2, _ := uuid.Parse("9846bf40-e380-4842-ae15-1b60996d1190")
	sgxUrl3, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5b2")

	tdxUrl1, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5bf")
	tdxUrl2, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5bi")
	tdxUrl3, _ := uuid.Parse("9846bf40-e380-4842-ae15-1b60996d1190")

	type fields struct {
		remoteManager *keymanager.RemoteManager
		policyStore   domain.KeyTransferPolicyStore
		keyConfig     domain.KeyTransferControllerConfig
		apsClient     apsClient.APSClient
		aasClient     *aasClient.Client
	}
	type args struct {
		tokenClaims    *aps.AttestationTokenClaim
		transferPolicy *kbs.KeyTransferPolicy
		keyAlgorithm   string
		userData       string
		keyId          uuid.UUID
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    interface{}
		want1   int
		wantErr bool
	}{
		{
			name: "Validate the claims and get RSA key with SGX transfer policy, should get a RSA key",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: false,
		},
		{
			name: "Validate the claims and get AES key with SGX transfer policy, should get a AES key",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "AES",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: false,
		},
		{
			name: "Validate the claims and get EC key with SGX transfer policy, should get a EC key",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "EC",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: false,
		},
		{
			name: "Validate the claims and get RSA key with TDX transfer policy, should get a RSA key",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: false,
		},
		{
			name: "Validate the claims and get key with empty MrSigner, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with empty MrSignerSeam, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with empty sgx attributes, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get Key with invalid policyID's, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with empty MrSeam, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get Key with invalid MrSeam, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f8972d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with empty MRTD, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{""},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with invalid MRTD, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf896414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with invalid MrEnclave, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c59b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get Key with empty TcbStatus, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with invalid SeamSvn, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &k,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with invalid RTMR0, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90bad43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
							MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &j,
							MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
							RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
							RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
							RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with invalid IsvProductId, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{2},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get Key with invalid IsvSvn, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &l,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with invalid keyId, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
							IsvSvn:             &i,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.Nil,
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with no sgx attributes, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
					IsvProductId: &pid,
					IsvSvn:       &i,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxUrl3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						PolicyIds: []uuid.UUID{
							sgxUrl1,
							sgxUrl2,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get key with no tdx attributes, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MrSeam:       "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
					SeamSvn:      &j,
					MRTD:         "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
					RTMR2:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					RTMR3:        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxUrl2,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						PolicyIds: []uuid.UUID{
							tdxUrl1,
							tdxUrl3,
						},
					},
				},
				keyAlgorithm: "RSA",
				userData:     base64.StdEncoding.EncodeToString(loadedPubKey),
				keyId:        uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := &KeyTransferController{
				remoteManager: tt.fields.remoteManager,
				policyStore:   tt.fields.policyStore,
				keyConfig:     tt.fields.keyConfig,
				apsClient:     tt.fields.apsClient,
				aasClient:     tt.fields.aasClient,
			}
			_, _, err := kc.validateClaimsAndGetKey(tt.args.tokenClaims, tt.args.transferPolicy, tt.args.keyAlgorithm, tt.args.keyId)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyTransferController.validateClaimsAndGetKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func loadPublicKey(userData []byte) ([]byte, error) {
	pubKeyBlock, _ := pem.Decode(userData)
	pubKeyBytes, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Public key format : <exponent:E_SIZE_IN_BYTES><modulus:N_SIZE_IN_BYTES>
	pub := pubKeyBytes.(*rsa.PublicKey)
	pubBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pubBytes, uint32(pub.E))
	pubBytes = append(pubBytes, pub.N.Bytes()...)
	return pubBytes, nil
}
