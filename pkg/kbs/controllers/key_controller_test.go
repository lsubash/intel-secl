/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	aasClient "github.com/intel-secl/intel-secl/v5/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/mocks"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/kmipclient"
	kbsRoutes "github.com/intel-secl/intel-secl/v5/pkg/kbs/router"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/context"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aas"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const (
	samlCertsDir          = "./resources/saml/"
	trustedCaCertsDir     = "./resources/trustedca/"
	tpmIdentityCertsDir   = "./resources/tpm-identity/"
	validSamlReportPath   = "./resources/saml_report.xml"
	invalidSamlReportPath = "./resources/invalid_saml_report.xml"
	endpointUrl           = "https://localhost:9443/kbs/v1"
	aasUrl                = "https://aas.com:8444/aas/v1"
	apsUrl                = "https://aps.com:5443/aps/v1/"
	jwtToken              = "test_token"
	cmsRootCa             = "MIIELDCCApSgAwIBAgIBADANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UEAxMFQ01TQ0EwHhcNMjIwMTA0MDkzMTMwWhcNMjcwMTA0MDkzMTMwWjBHMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UEAxMFQ01TQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfrDvpjCTgS7qdFom5xyrg80eqsT3CCtSSx7W33XJ6Y4ELDjP3L238XieEvwrQjB1l8ReHC4RspWf7Mhlu5oUioc9dWHErwLy6AdokJnnKZNCcgHTz2rRAIahFbT9iRRTAg6/B5Ya+9s9SSLZcWNe7caXAhQeABssrjZSNrh1aYj9GSq8bnExO1AVNJzFBBnYn5OzjWecvaaysMNel624wHcwRyq33u+dBITuYSeE1kXG3mTWG/gxXrW89ONuLpxAn12iWsZtJ2USzcg8dURTHNoqI63dnr3jCW9OFfFchAuFkQnIzI3PV2MI30Ku2Me6ZCk6F+1HunChbqwaGlZ/klCOgiHZCtTBqKJfqXC7BftGjynwtPTNh/HIGfWMSaPF+kxcHkpnBwNC4ZkMnhgn62GK2WKPJwGTYZ8iFZ4X3duRowZA/uMK/LiYzBpI0MRg/OgQn4vcm+FIh4CiOCcwK3QT3c83MMbRq7CdRz4cXVwD/uh7mEC6YettvqCqXSQMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggGBABNWn4uDanR6uYnydUNguMEBYf5Up381RC+lwIAv51aDhMx7/mPcApBJWTIjpOTMorDUiGiXUnKkPoKx3ulNPeq+QCoAaZgvsZzK8wixuTTPDBJ2yOs34zBoRNzPFptDbf4drXZq8UeIwDFo5LVCMONFxE/wDaDfc2f/XKIJghHf6dDZZG9mCgIDpWRy/CrkHg4GYomW81QSI/rIyorMPUIHG8ydh/vpM5T7jJKaDq5fNc67ePxFo5WuNUFA+QO+0VAfpvQwYmjrD/BfxJ62Abwc7oZoFJ+iutwoe1Cap5IN7vorZ5C8idqcKnln8k6bLbFb+Ud7F9GNJwP/mSgf/rYIO+T0ovVRmyF8XFCaD3TIyT28MCsNDn0eanEveg1JHZcsh9HaryWIuFG4cQJnLRoKRROkLtpElmrwk7zvG8yM6Eus7PGyGcnSuEH/Zs8NdGxcuLCkB3IBESG/CXP261e1HpBvSOg3lxdojOvBZsHeQHStcmFJXIXV2gWVeM+Ocg=="
)

var _ = Describe("KeyController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var keyStore *mocks.MockKeyStore
	var policyStore *mocks.MockKeyTransferPolicyStore
	var remoteManager *keymanager.RemoteManager
	var keyController *controllers.KeyController
	var keyTransferController *controllers.KeyTransferController

	keyPair, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &keyPair.PublicKey
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	var publicKeyInPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	validEnvelopeKey := pem.EncodeToMemory(publicKeyInPem)
	invalidEnvelopeKey := strings.Replace(strings.Replace(string(validEnvelopeKey), "-----BEGIN PUBLIC KEY-----\n", "", 1), "-----END PUBLIC KEY-----", "", 1)
	validSamlReport, _ := ioutil.ReadFile(validSamlReportPath)
	invalidSamlReport, _ := ioutil.ReadFile(invalidSamlReportPath)

	mockClient := kmipclient.NewMockKmipClient()
	mockClient.On("CreateSymmetricKey", mock.Anything, mock.Anything).Return("1", nil)
	mockClient.On("DeleteKey", mock.Anything).Return(nil)
	mockClient.On("GetKey", mock.Anything).Return([]byte(""), nil)
	keyManager := keymanager.NewKmipManager(mockClient)

	aasClient := aasClient.NewMockAASClient()
	aasClient.On("GetJwtSigningCertificate", mock.Anything).Return(controllers.JwtSignCert, nil)

	var caCerts []x509.Certificate
	cmsCA, _ := base64.StdEncoding.DecodeString(cmsRootCa)

	cert, _ := x509.ParseCertificate(cmsCA)

	caCerts = append(caCerts, *cert)

	apsClient := aps.NewMockApsClient()
	apsClient.On("GetAttestationToken", mock.Anything, mock.Anything).Return(controllers.Token, 0, nil)
	apsClient.On("GetJwtSigningCertificate").Return(controllers.JwtSignCert, nil)
	apsClient.On("GetNonce", mock.Anything).Return("test_nonce", 200, nil)

	newId, _ := uuid.NewRandom()
	kcc := domain.KeyTransferControllerConfig{
		SamlCertsDir:        samlCertsDir,
		TrustedCaCertsDir:   trustedCaCertsDir,
		TpmIdentityCertsDir: tpmIdentityCertsDir,
	}

	BeforeEach(func() {
		router = mux.NewRouter()
		keyStore = mocks.NewFakeKeyStore()
		policyStore = mocks.NewFakeKeyTransferPolicyStore()
		remoteManager = keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)
		keyController = controllers.NewKeyController(remoteManager, policyStore, newId)
		keyTransferController = controllers.NewKeyTransferController(remoteManager, policyStore, kcc, apsClient, aasClient)
	})

	// Specs for HTTP Post to "/keys"
	Describe("Create a new Key", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 256
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a Create request that contains non-existent key-transfer-policy", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 256
								 },
								 "transfer_policy_id": ""
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request with invalid transfer policy id", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `
					 {
						 "key_information": {
							 "algorithm": "AES",
							 "key_length": 256
						 },
						 "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9"
					 }
				 `

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without algorithm", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "key_length": 256
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid algorithm", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "XYZ",
									 "key_length": 256
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without key length", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES"
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid key length", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 123
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without curve type", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "EC"
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid curve type", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "EC",
									 "curve_type": "xyz123"
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request with no content", func() {
			It("Should fail to create a new Key with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(""),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request with unsupported content type", func() {
			It("Should fail to create a new Key with unsupported media type error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 256
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("Provide a Create request with invalid permissions", func() {
			It("Should fail to create a new Key with unauthorized error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 256
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide a Create request with valid key string,kmip key id and invalid permissions", func() {
			It("Should fail to create a new Key with unauthorized error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 256,
									 "key_string": "test",
									 "kmip_key_id": "1"
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
	})

	Describe("Register a new Key", func() {
		Context("Provide a valid Register request", func() {
			It("Should register a new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 256,
									 "kmip_key_id": "1"
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.KeyRegister},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a Register request that contains malformed key", func() {
			It("Should fail to register new Key", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Create))).Methods(http.MethodPost)
				keyJson := `{
								 "key_information": {
									 "algorithm": "AES",
									 "key_length": 256,
									 "key_string": "k@y"
								 }
							 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(keyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Post to "/keys/{id}/transfer"
	Describe("Transfer using public key", func() {
		Context("Provide a valid public key", func() {
			It("Should transfer an existing symmetric Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods(http.MethodPost)
				envelopeKey := string(validEnvelopeKey)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(envelopeKey),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a valid public key", func() {
			It("Should transfer an existing Private Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods(http.MethodPost)
				envelopeKey := string(validEnvelopeKey)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/87d59b82-33b7-47e7-8fcb-6f7f12c82719/transfer",
					strings.NewReader(envelopeKey),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a public key without PUBLIC KEY headers", func() {
			It("Should fail to transfer Key with bad request error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods(http.MethodPost)
				envelopeKey := invalidEnvelopeKey

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(envelopeKey),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a public key without DER data", func() {
			It("Should fail to transfer Key with bad request error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods(http.MethodPost)
				envelopeKey := `-----BEGIN PUBLIC KEY-----
 -----END PUBLIC KEY-----`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(envelopeKey),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a non-existent Key id", func() {
			It("Should fail to transfer key with not found error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Transfer))).Methods(http.MethodPost)
				envelopeKey := string(validEnvelopeKey)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer",
					strings.NewReader(envelopeKey),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	Describe("Transfer key with evidence", func() {
		Context("provide an invalid attestation token for SGX attestation", func() {
			It("Should fail to transfer key with unauthorized error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Authorization", "Bearer "+controllers.Token)
				req.Header.Set("Attestation-Type", "SGX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide an invalid attestation token for TDX attestation", func() {
			It("Should fail to transfer key with unauthorized error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Attestation-Type", "TDX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide a valid request and trigger internal server error from backend", func() {
			It("Should fail to transfer key with internal server error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				keyStore.ThrowError = true
				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/6aa9cd48-dbf2-11ec-9d64-0242ac120002/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Authorization", "Bearer "+controllers.Token)
				req.Header.Set("Attestation-Type", "SGX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
		Context("Provide an empty nonce in request header", func() {
			It("Should fail to transfer key with unauthorized error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Attestation-Type", "TDX")
				req.Header.Set("Nonce", "")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide an invalid keyid", func() {
			It("Should fail to transfer key with not found error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e4/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Authorization", "Bearer "+controllers.Token)
				req.Header.Set("Attestation-Type", "SGX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("provide an empty bearer token to transfer", func() {
			It("Should fail to transfer key with unauthorized error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Authorization", "")
				req.Header.Set("Attestation-Type", "SGX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide an empty nonce and content", func() {
			It("Should fail to transfer key with no content error ", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
					bytes.NewBuffer([]byte("")),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Attestation-Type", "TDX")
				req.Header.Set("Nonce", "")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Provide an empty nonce and invalid content type", func() {
			It("Should fail to transfer key with unsupported media type error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				req.Header.Set("Attestation-Type", "TDX")
				req.Header.Set("Nonce", "")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide an invalid content type", func() {
			It("Should fail to transfer key with unsupported media type error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				req.Header.Set("Attestation-Type", "TDX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("Provide an empty content", func() {
			It("Should fail to transfer key with bad request error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
					bytes.NewBuffer([]byte("")),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Attestation-Type", "TDX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide an unmatched attestation type", func() {
			It("Should fail to transfer key with unauthorized error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.Transfer))).Methods(http.MethodPost)

				request := &kbs.KeyTransferRequest{
					AttestationToken: "test_token",
				}

				reqBytes, _ := json.Marshal(request)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ed37c360-7eae-4250-a677-6ee12adce8e3/transfer",
					bytes.NewBuffer(reqBytes),
				)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Authorization", "Bearer "+controllers.Token)
				req.Header.Set("Attestation-Type", "SGX")
				req.Header.Set("Nonce", "test_token")

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
	})

	Describe("Transfer using saml report", func() {
		Context("Provide a valid saml report", func() {
			It("Should transfer an existing Key", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.TransferWithSaml))).Methods(http.MethodPost)
				samlReport := string(validSamlReport)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a saml report with overall trust false", func() {
			It("Should fail to transfer Key with unauthorized error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.TransferWithSaml))).Methods(http.MethodPost)
				samlReport := strings.ReplaceAll(string(validSamlReport), "true", "false")

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide a saml report with unknown signer", func() {
			It("Should fail to transfer Key with unauthorized error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.TransferWithSaml))).Methods(http.MethodPost)
				samlReport := string(invalidSamlReport)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Provide an invalid saml report", func() {
			It("Should fail to transfer Key with bad request error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.TransferWithSaml))).Methods(http.MethodPost)
				samlReport := `saml`

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a saml report with unsupported accept type", func() {
			It("Should fail to transfer key with unsupported media type error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.TransferWithSaml))).Methods(http.MethodPost)
				samlReport := string(validSamlReport)

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("Provide an empty saml report", func() {
			It("Should fail to transfer key with bad request error", func() {
				router.Handle("/keys/{id}/transfer", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferController.TransferWithSaml))).Methods(http.MethodPost)
				samlReport := ""

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys/ee37c360-7eae-4250-a677-6ee12adce8e2/transfer",
					strings.NewReader(samlReport),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeOctetStream)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/keys/{id}"
	Describe("Retrieve an existing Key", func() {
		Context("Retrieve Key by ID", func() {
			It("Should retrieve a Key", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve Key by non-existent ID", func() {
			It("Should fail to retrieve key with not found error", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/keys/{id}"
	Describe("Delete an existing Key", func() {
		Context("Delete Key by ID", func() {
			It("Should delete a Key", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/keys/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete Key by non-existent ID", func() {
			It("Should fail to delete Key with not found error", func() {
				router.Handle("/keys/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/keys/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/keys"
	Describe("Search for all the Keys", func() {
		Context("Get all the Keys", func() {
			It("Should get list of all the Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				_ = json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 4 keys
				Expect(len(keyResponses)).To(Equal(4))
			})
		})
		Context("Get all the Keys with unknown query parameter", func() {
			It("Should fail to get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?badparam=value", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid algorithm param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?algorithm=AES", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				_ = json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 2 keys
				Expect(len(keyResponses)).To(Equal(2))
			})
		})
		Context("Get all the Keys with invalid algorithm param", func() {
			It("Should fail to get Keys with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?algorithm=AE$", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid keyLength param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?keyLength=256", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				_ = json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 2 keys
				Expect(len(keyResponses)).To(Equal(2))
			})
		})
		Context("Get all the Keys with invalid keyLength param", func() {
			It("Should fail to get Keys with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?keyLength=abc", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid curveType param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?curveType=prime256v1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				_ = json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 1 key
				Expect(len(keyResponses)).To(Equal(1))
			})
		})
		Context("Get all the Keys with invalid curveType param", func() {
			It("Should fail to get Keys with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?curveType=primev!", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Keys with valid transferPolicyId param", func() {
			It("Should get list of all the filtered Keys", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?transferPolicyId=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var keyResponses []kbs.KeyResponse
				_ = json.Unmarshal(w.Body.Bytes(), &keyResponses)
				// Verifying mocked data of 3 keys
				Expect(len(keyResponses)).To(Equal(3))
			})
		})
		Context("Get all the Keys with invalid transferPolicyId param", func() {
			It("Should fail to get Keys with bad request error", func() {
				router.Handle("/keys", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/keys?transferPolicyId=e57e5ea0-d465-461e-882d-", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
