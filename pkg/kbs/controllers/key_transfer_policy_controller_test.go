/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/mocks"
	kbsRoutes "github.com/intel-secl/intel-secl/v5/pkg/kbs/router"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("KeyTransferPolicyController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var keyStore *mocks.MockKeyStore
	var policyStore *mocks.MockKeyTransferPolicyStore
	var keyTransferPolicyController *controllers.KeyTransferPolicyController
	BeforeEach(func() {
		router = mux.NewRouter()
		keyStore = mocks.NewFakeKeyStore()
		policyStore = mocks.NewFakeKeyTransferPolicyStore()

		keyTransferPolicyController = controllers.NewKeyTransferPolicyController(policyStore, keyStore)
	})

	// Specs for HTTP Post to "/key-transfer-policies"
	Describe("Create a new Key Transfer Policy for SGX", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
					"attestation_type":[
					   "SGX"
					],
					"sgx":{
					   "attributes":{
						  "mrsigner":[
							 "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
						  ],
						  "isvprodid":[
							 12
						  ],
						  "mrenclave":[
							 "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
						  ],
						  "isvsvn":1,
						  "client_permissions":[
							 "nginx",
							 "USA"
						  ],
						  "enforce_tcb_upto_date":false
					   }
					}
				 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a valid Create request for TDX", func() {
			It("Should create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["TDX"],
							"tdx": {
								"attributes": {
									"mrsignerseam": [
										"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
									],
									"mrseam": [
										"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
									],
									"seamsvn": 0,
									"mrtd": [
										"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
									],
									"rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
									"rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
									"rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a invalid Create request for TDX - invalid rtmr0", func() {
			It("Should not create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["TDX"],
							"tdx": {
								"attributes": {
									"mrsignerseam": [
										"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
									],
									"mrseam": [
										"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
									],
									"seamsvn": 0,
									"mrtd": [
										"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
									],
									"rtmr0": "test123",
									"rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
									"rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid Create request for TDX -invalid rtmr1", func() {
			It("Should not create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["TDX"],
							"tdx": {
								"attributes": {
									"mrsignerseam": [
										"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
									],
									"mrseam": [
										"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
									],
									"seamsvn": 0,
									"mrtd": [
										"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
									],
									"rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
									"rtmr1": "test123",
									"rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a invalid Create request", func() {
			It("Should not create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["SGX"],
							"sgx": {
								"attributes": {
									"mrsigner": [
                      "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
                  ],
                  "isvprodid": [
                      12
                  ],
                  "mrenclave": 
                      "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
                  "isvsvn": 1,
                  "client_permissions": [
                      "nginx",
                      "USA"
                  ],
                  "enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid Create request without attestation type", func() {
			It("Should not create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"sgx": {
								"attributes": {
									"mrsigner": [
                      "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
                  ],
                  "isvprodid": [
                      12
                  ],
                  "mrenclave": [
                      "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
                  ],
                  "isvsvn": 1,
                  "client_permissions": [
                      "nginx",
                      "USA"
                  ],
                  "enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid Create request with empty attestation type", func() {
			It("Should not create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": [],
							"sgx": {
								"attributes": {
									"mrsigner": [
                      "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
                  ],
                  "isvprodid": [
                      12
                  ],
                  "mrenclave": [
                      "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
                  ],
                  "isvsvn": 1,
                  "client_permissions": [
                      "nginx",
                      "USA"
                  ],
                  "enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid Create request with invalid attestation type", func() {
			It("Should not create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["test"],
							"sgx": {
								"attributes": {
									"mrsigner": [
                      "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
                  ],
                  "isvprodid": [
                      12
                  ],
                  "mrenclave": [
                      "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
                  ],
                  "isvsvn": 1,
                  "client_permissions": [
                      "nginx",
                      "USA"
                  ],
                  "enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid Create request for TDX", func() {
			It("Should not create a new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["TDX"],
							"tdx": {
								"attributes": {
									"mrsignerseam": [
										"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
									],
									"mrseam": [
										"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
									],
									"seamsvn": 0,
									"mrtd": "b90abd4373638",
									"rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
									"rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
									"rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"enforce_tcb_upto_date": false
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without mrsigner", func() {
			It("Should fail to create new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["SGX"],
							"sgx": {
								"attributes": {
									"isvprodid": [0]
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without isvprodid", func() {
			It("Should fail to create new Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Create))).Methods(http.MethodPost)
				policyJson := `{
							"attestation_type": ["SGX"],
							"sgx": {
								"attributes": {
									"mrsigner": ["cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"]
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/key-transfer-policies",
					strings.NewReader(policyJson),
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

	// Specs for HTTP Get to "/key-transfer-policies/{id}"
	Describe("Retrieve an existing Key Transfer Policy", func() {
		Context("Retrieve Key Transfer Policy by ID", func() {
			It("Should retrieve a Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/key-transfer-policies/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve Key Transfer Policy by non-existent ID", func() {
			It("Should fail to retrieve Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/key-transfer-policies/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Put to "/key-transfer-policies/{id}"
	Describe("Update Key Transfer Policy", func() {
		Context("Provide a valid Update request", func() {
			It("Should update an existing  Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Update))).Methods(http.MethodPut)
				policyJson := `{
							"attestation_type": ["SGX"],
							"sgx": {
								"attributes": {
									"mrsigner": ["dd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
									"isvprodid": [0]
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/key-transfer-policies/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Update Key Transfer Policy by non-existent ID", func() {
			It("Should fail to update Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Update))).Methods(http.MethodPut)
				policyJson := `{
					"attestation_type": ["SGX"],
					"sgx": {
						"attributes": {
							"mrsigner": ["dd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
							"isvprodid": [0]
						}
					}
				}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/key-transfer-policies/e57e5ea0-d465-461e-882d-1600090caa0d",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Provide a valid Update request - TDX", func() {
			It("Should update an existing  Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Update))).Methods(http.MethodPut)
				policyJson := `{
							"attestation_type": ["TDX"],
							"tdx": {
								"attributes": {
									"mrsignerseam": [
										"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
									],
									"mrseam": [
										"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
									],
									"seamsvn": 0
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/key-transfer-policies/ed37c360-7eae-4250-a677-6ee12adce8e3",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a Update request with no content", func() {
			It("Should update an existing  Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Update))).Methods(http.MethodPut)

				req, err := http.NewRequest(
					http.MethodPut,
					"/key-transfer-policies/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(""),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid Update request", func() {
			It("Should update an existing  Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Update))).Methods(http.MethodPut)
				policyJson := `{
							"attestation_type": ["TDX"],
							"tdx": {
								"attributes": {
									"mrseam": [
										"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
									],
									"seamsvn": 0
								}
							}
						}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/key-transfer-policies/ed37c360-7eae-4250-a677-6ee12adce8e3",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid Update request - invalid content type", func() {
			It("Should update an existing  Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Update))).Methods(http.MethodPut)
				policyJson := `{
					"attestation_type": ["SGX"],
					"sgx": {
						"attributes": {
							"mrsigner": ["dd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
							"isvprodid": [0]
						}
					}
				}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/key-transfer-policies/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(policyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
	})

	// Specs for HTTP Delete to "/key-transfer-policies/{id}"
	Describe("Delete an existing Key Transfer Policy", func() {
		Context("Delete Key Transfer Policy by ID", func() {
			It("Should delete a Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferPolicyController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/key-transfer-policies/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete Key Transfer Policy by non-existent ID", func() {
			It("Should fail to delete Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferPolicyController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/key-transfer-policies/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Delete Key Transfer Policy associated with Key", func() {
			It("Should fail to delete Key Transfer Policy", func() {
				router.Handle("/key-transfer-policies/{id}", kbsRoutes.ErrorHandler(kbsRoutes.ResponseHandler(keyTransferPolicyController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/key-transfer-policies/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/key-transfer-policies"
	Describe("Search for all the Key Transfer Policies", func() {
		Context("Get all the Key Transfer Policies", func() {
			It("Should get list of all the Key Transfer Policies", func() {
				router.Handle("/key-transfer-policies", kbsRoutes.ErrorHandler(kbsRoutes.JsonResponseHandler(keyTransferPolicyController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/key-transfer-policies", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var policies []kbs.KeyTransferPolicy
				_ = json.Unmarshal(w.Body.Bytes(), &policies)
				// Verifying mocked data of 2 key transfer policies
				Expect(len(policies)).To(Equal(3))
			})
		})
	})
})
