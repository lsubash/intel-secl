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
	mrEnclave = "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
	mrSigner  = "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
	policyID  = "ee37c360-7eae-4250-a677-6ee12adce8e2"
	keyID     = "87d59b82-33b7-47e7-8fcb-6f7f12c82719"
	mrValue   = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	mrSeam    = "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
	mrtd      = "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
	rtmr0     = "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14"
	rtmr1     = "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b"
)

var Token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"

var JwtSignCert = []byte(`-----BEGIN CERTIFICATE-----
 MIID/jCCAuagAwIBAgIUH4Solwfy9/iP2Ax/JpXHHJ7Yxq8wDQYJKoZIhvcNAQEL
 BQAwgZExCzAJBgNVBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExETAPBgNV
 BAcTCFNjcmFudG9uMREwDwYDVQQKFAhURVNUX0lOQzEQMA4GA1UECxMHVEVTVElO
 RzEZMBcGA1UEAxQQVEVTVF9DRVJUSUZJQ0FURTEYMBYGCSqGSIb3DQEJARYJVEVT
 VF9DRVJUMB4XDTIyMDQwNzA5NDEwMFoXDTMyMDQwNzA5NDEwMFowgZExCzAJBgNV
 BAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExETAPBgNVBAcTCFNjcmFudG9u
 MREwDwYDVQQKFAhURVNUX0lOQzEQMA4GA1UECxMHVEVTVElORzEZMBcGA1UEAxQQ
 VEVTVF9DRVJUSUZJQ0FURTEYMBYGCSqGSIb3DQEJARYJVEVTVF9DRVJUMIIBIjAN
 BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCkhYcR164s4kKU3+fTbrXTvwkfC
 hgcw6pSmVJssTzRxshqIeMJ2B391sBB9O/g91OLX6VUEsp3QWa3vESk34ZM1NQ//
 MIfS91+v5rsKhCZQHwDyf9dWfGW3UIB404JihX9vSaK3zNTCPSw8/2SGsg8IRori
 imf1TqOZy6qKtFa5B6WVHw+xUTetGOmAYZCdaqAITlGF2Wyex5xQtgwO5Kw7szst
 hvQ5tbeXPjJVWeItNP/PKvHx1mp84gS7cUMjO9tmr8XUNmCelxGqJ1fnxhkD/lrY
 AP6mhBNqllEecWHv5nczfwqeS3xRI9Weh2KzOu9t3R9XAKq8T+qYt5/izQIDAQAB
 o0wwSjAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIE8DALBgNVHQ8EBAMCBaAw
 HQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IB
 AQCi/Hj1lcW36EA59eYT8ELHKNwlnZfZD5hQaBSb7LcjzKajDtF3rzIDsGSAmldC
 bw1CeVMTeIMoNxSBPxAPFHK1EFMP59VrXUoI8ZiZll6CaqDHHjsTPO/5T9Lz9Jjf
 3hu4ixOEJmfV1WEO8QzZrJwFcIkefUWLhpiJW1SNtlTR3D0GlmyMuO73mzr64yx7
 ouAW4RSU11gVIZfobSs6g7hlIrbMz71wbiaCQQ6MN015DyEpPI7lrhOPvz3lOveW
 4fe8ARWwVlEd3AzN8ZlY3s6oaAqY2d4T/u/v6nK4S88a/uAYB1wwQDSYp6LslG1d
 uKYodDFCQ0NYU4Xz2lbzn5KV
 -----END CERTIFICATE-----`)

func TestKeyTransferControllerAuthenticateToken(t *testing.T) {

	var caCerts []x509.Certificate
	cmsCA, _ := base64.StdEncoding.DecodeString(CmsRootCa)

	cert, _ := x509.ParseCertificate(cmsCA)

	caCerts = append(caCerts, *cert)

	mockAps := apsClient.NewMockApsClient()
	mockAps.On("GetAttestationToken", mock.Anything, mock.Anything).Return(Token, 0, nil)
	mockAps.On("GetJwtSigningCertificate").Return(JwtSignCert, nil)

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
			name: "Provide an invalid token which key id doesn't matches with jwtsigningcert hash, should fail to authenticate",
			fields: fields{
				keyConfig: domain.KeyTransferControllerConfig{
					AasBaseUrl: "https://aas.com:8444/aas/v1/",
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

func TestKeyTransferControllerValidateClaimsAndGetKey(t *testing.T) {
	var isvSvn uint16 = 0
	var seamSvn uint8 = 0
	var seamSvnVal uint8 = 1
	var isvSvnVal uint16 = 1
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

	loadedPubKey := loadPublicKey(pub)

	sgxPolicyId1, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5bf")
	sgxPolicyId2, _ := uuid.Parse("9846bf40-e380-4842-ae15-1b60996d1190")
	sgxPolicyId3, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5b2")

	tdxPolicyId1, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5bf")
	tdxPolicyId2, _ := uuid.Parse("9846bf40-e380-4842-ae15-1b60996d1190")
	tdxPolicyId3, _ := uuid.Parse("37965f5f-ccaf-4cdc-a356-a8ed5268a5bi")

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
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
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
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "AES",
				keyId:        uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
			},
			wantErr: false,
		},
		{
			name: "Validate the claims and get EC key with SGX transfer policy, should fail to get a EC key as this alg not supported in transferkey",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "EC",
				keyId:        uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
			},
			wantErr: true,
		},
		{
			name: "Validate the claims and get RSA key with TDX transfer policy, should get a RSA key",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{mrSeam},
							SeamSvn:            &seamSvn,
							MRTD:               []string{mrtd},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: false,
		},
		{
			name: "Provide an empty MrSigner, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     "",
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an empty MrSignerSeam, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: "",
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{mrSeam},
							SeamSvn:            &seamSvn,
							MRTD:               []string{mrtd},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an empty sgx attributes, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					TeeHeldData:  base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid policyID's, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
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
					MrSignerSeam: mrValue,
					MrSeam:       "",
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{mrSeam},
							SeamSvn:            &seamSvn,
							MRTD:               []string{mrtd},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid MrSeam, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{"0f8972d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
							SeamSvn:            &seamSvn,
							MRTD:               []string{mrtd},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
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
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{mrSeam},
							SeamSvn:            &seamSvn,
							MRTD:               []string{""},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid MRTD, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         "cf896414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{mrSeam},
							SeamSvn:            &seamSvn,
							MRTD:               []string{mrtd},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid MrEnclave, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    "01c59b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
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
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid token with wrong TeeHeldData, should fail to get key",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: "test123",
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid SeamSvn, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvnVal,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{mrSeam},
							SeamSvn:            &seamSvn,
							MRTD:               []string{mrtd},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid RTMR0, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        "b90bad43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						Attributes: &kbs.TdxAttributes{
							MrSignerSeam:       []string{mrValue},
							MrSeam:             []string{mrSeam},
							SeamSvn:            &seamSvn,
							MRTD:               []string{mrtd},
							RTMR0:              rtmr0,
							RTMR1:              rtmr1,
							RTMR2:              mrValue,
							RTMR3:              mrValue,
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid IsvProductId, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{2},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid IsvSvn, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvnVal,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide an invalid keyId, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						Attributes: &kbs.SgxAttributes{
							MrSigner:           []string{mrSigner},
							IsvProductId:       []uint16{1},
							MrEnclave:          []string{mrEnclave},
							IsvSvn:             &isvSvn,
							ClientPermissions:  []string{"nginx", "USA"},
							EnforceTCBUptoDate: func(b bool) *bool { return &b }(true),
						},
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.Nil,
			},
			wantErr: true,
		},
		{
			name: "Provide no sgx attributes in transfer policy, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrEnclave:    mrEnclave,
					MrSigner:     mrSigner,
					IsvProductId: &pid,
					IsvSvn:       &isvSvn,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						sgxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.SGX},
					SGX: &kbs.SgxPolicy{
						PolicyIds: []uuid.UUID{
							sgxPolicyId1,
							sgxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
			},
			wantErr: true,
		},
		{
			name: "Provide no tdx attributes in transfer policy, should fail to validate",
			fields: fields{
				remoteManager: remote_manager,
			},
			args: args{
				tokenClaims: &aps.AttestationTokenClaim{
					MrSignerSeam: mrValue,
					MrSeam:       mrSeam,
					SeamSvn:      &seamSvn,
					MRTD:         mrtd,
					RTMR0:        rtmr0,
					RTMR1:        rtmr1,
					RTMR2:        mrValue,
					RTMR3:        mrValue,
					TcbStatus:    "OK",
					PolicyIds: []uuid.UUID{
						tdxPolicyId3,
					},
					TeeHeldData: base64.StdEncoding.EncodeToString(loadedPubKey),
				},
				transferPolicy: &kbs.KeyTransferPolicy{
					ID:              uuid.MustParse(policyID),
					CreatedAt:       time.Now().UTC(),
					AttestationType: []aps.AttestationType{aps.TDX},
					TDX: &kbs.TdxPolicy{
						PolicyIds: []uuid.UUID{
							tdxPolicyId1,
							tdxPolicyId2,
						},
					},
				},
				keyAlgorithm: "RSA",
				keyId:        uuid.MustParse(keyID),
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

func loadPublicKey(userData []byte) []byte {
	pubKeyBlock, _ := pem.Decode(userData)
	pubKeyBytes, _ := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)

	// Public key format : <exponent:E_SIZE_IN_BYTES><modulus:N_SIZE_IN_BYTES>
	pub := pubKeyBytes.(*rsa.PublicKey)
	pubBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pubBytes, uint32(pub.E))
	pubBytes = append(pubBytes, pub.N.Bytes()...)
	return pubBytes
}
