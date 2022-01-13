/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v5/pkg/wls/domain/mocks"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	wlsRoutes "github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	"strings"
)

var _ = Describe("ReportController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var reportStore *mocks2.MockReportStore
	var reportController *controllers.ReportController

	BeforeEach(func() {
		router = mux.NewRouter()
		reportStore = mocks2.NewMockReportStore()
		reportController = controllers.NewReportController(reportStore)
	})

	Describe("Create Report", func() {
		Context("When a empty Report Create Request is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				// Create Request body
				createfReq := ``
				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When a VALID Report Create Request is passed", func() {
			It("A new Report record is created and HTTP Status: 201 response is received", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				createfReq := `{
					"instance_manifest": {
						"instance_info": {
							"instance_id": "bd06385a-5530-4644-a510-e384b8c3323a",
								"host_hardware_uuid": "00964993-89c1-e711-906e-00163566263e",
								"image_id": "773e22da-f687-47ca-89e7-5df655c60b7b"
						},
						"image_encrypted": true
					},
					"policy_name": "Intel VM Policy",
						"results": [
				{
				"rule": {
				"rule_name": "EncryptionMatches",
				"markers": [
				"IMAGE"
				],
				"expected": {
				"name": "encryption_required",
				"value": true
				}
				},
				"flavor_id": "3a3e1ccf-2618-4a0d-8426-fb7acb1ebabc",
				"trusted": true
				}
				],
				"trusted": true,
				"data": "eyJpbnN0YW5jZV9tYW5pZmVzdCI6eyJpbnN0YW5jZV9pbmZvIjp7Imluc3RhbmNlX2lkIjoiYmQwNjM4NWEtNTUzMC00NjQ0LWE1MTAtZTM4NGI4YzMzMjNhIiwiaG9zdF9oYXJkd2FyZV91dWlkIjoiMDA5NjQ5OTMtODljMS1lNzExLTkwNmUtMDAxNjM1NjYyNjNlIiwiaW1hZ2VfaWQiOiI3NzNlMjJkYS1mNjg3LTQ3Y2EtODllNy01ZGY2NTVjNjBiN2IifSwiaW1hZ2VfZW5jcnlwdGVkIjp0cnVlfSwicG9saWN5X25hbWUiOiJJbnRlbCBWTSBQb2xpY3kiLCJyZXN1bHRzIjpbeyJydWxlIjp7InJ1bGVfbmFtZSI6IkVuY3J5cHRpb25NYXRjaGVzIiwibWFya2VycyI6WyJJTUFHRSJdLCJleHBlY3RlZCI6eyJuYW1lIjoiZW5jcnlwdGlvbl9yZXF1aXJlZCIsInZhbHVlIjp0cnVlfX0sImZsYXZvcl9pZCI6IjNhM2UxY2NmLTI2MTgtNGEwZC04NDI2LWZiN2FjYjFlYmFiYyIsInRydXN0ZWQiOnRydWV9XSwidHJ1c3RlZCI6dHJ1ZX0=",
				"hash_alg": "SHA-256",
				"cert": "-----BEGIN CERTIFICATE-----\nMIIEkTCCA3mgAwIBAgIJAPZIe4/J1rS4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\nBAMTEG10d2lsc29uLXBjYS1haWswHhcNMTkwNDMwMDM0MjI3WhcNMjkwNDI3MDM0\nMjI3WjAlMSMwIQYDVQQDDBpDTj1TaWduaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJHAH8O1VLhSIxy3pa5MUemtrJQw\nONd3+JzO6wq5hRYf5iBOK1ADbAF0iLjGV0CXWYNVIQgCahqmn5TQGGFjsLZ4XpDy\nUmCkYsMzqZxcjGZr/dgmXci50v9o2m7FoQgt1eo6JEcB3NYwCkEHzEkx0Ns6cFul\nx9wsYUgU0CwRt2lderLJFs8O5ojKuID+6+bfJM+mGNmGfMudFDsSyJbw8uVqJN/w\njQNGhFIpapLabxcPrhwlUAf5efjldeKgoP/QFdOBolRT3R5HiCc4A28EwR+KpCsz\n2SnPtI7rJHiPZlsNYncroXSKkB2S7EXiFEnd0uME6Mhicg0dZ0U+yC+vEA8CAwEA\nAaOCAcwwggHIMA4GA1UdDwEB/wQEAwIGwDCBnQYHVQSBBQMCKQSBkf9UQ0eAFwAi\nAAvMr4Y5+2EueRqQYi93bUkUj0N+bRncFS9UlxfZLDbcpwAEAP9VqgAAAAAAFALJ\nAAAABQAAAAABAAcAKAAIMgAAIgALTGEwky4u3fkb0E2zIcrc6ernZN3qq3Ma4658\n19uM8tkAIgAL9bsq9DzOiSKNpNm6DNfh9SmdEZvY8cpOW+G/Ue0DLbswggEUBghV\nBIEFAwIpAQSCAQYAFAALAQCFbPimpFjbGCJ6+psrVrxu2vqY631OYyLg8xGaDdAh\nY2SEaZUub93Jp/UfmZt3bP2inG4kKhvmKAiIHHlRf+aFCZ7SJMNGrh9o6TwmVaiz\nT35YVjZpO6xFEmdv5eQIxYKCmE301QwHrvymqW+TeCPe8BWRtCcXA2Vuskf18xI9\nVafYJUSHC9NSk85538AbztXgJidOUgARpTweDJt8u3v2lkpZlhRk3+7kOkyI3xv+\nvvKeWaQokfkJiCWTCNT7vSVc14YKs4o4bXnYiwzpFtHuypMcBtcliDh12xnowGHs\nx7helzw/ue1ACQRHHhDuPDY1VECmuN/qUNRXunWrJTvXMA0GCSqGSIb3DQEBCwUA\nA4IBAQADtwxXKk6PaXKB1iFSyUAY4IQF3296xcYddGy6XxyLZH+ePkr/xmzBPbSW\nlzYgnDaJ+bohzJqio+abm1ovRahlEgCHLZatHvIcWbBqFpLgMw1Z2xTulcwuGtW/\nOSMKM/LfU1T8dyDisXojTsby2Rxj2wsfWC3GXrPWOkefkEC4qVyo7VXOVuAxZhPw\ni3ysiWPjTDnEHAJVqCtqsWSZHSwcpDeRnntMQ8GV6K+4TCZ6rcD9a47ArlvCKKoI\nNKFXK5xW8/xwaVikyMBAqlXjjWnS4HcIh7BYTj55Dxy9qjJJDBfqgXi7t8t7no2F\nBZRD/3W7YmEExAsSvX8Y4naY4rpU\n-----END CERTIFICATE-----\n",
				"signature": "KcC6UI6C5vLDrBIQx/EU9ceNPJDP6fjrF7F+6pxJYoA50rwx7ZI0ULbL2HXQiD82oQltqzj/n0KzY8JxY0PhIuG1w2vF58xOOzlxFP4w3BF6PSMW7wggwr1sj0TvlLcoyO7jXiK4nIlNfOqj6VaS/ynzMDGSSZvYkQ46SvAVdd0k57jHNG4TBrlqW+PWrM3xsqUrUeSVWCTH13G7qk6P4yPBnSerbmMBT4zuiodL+B0FsSlXorE6bZ/zt2N836DtL42eIbc7YXigLtvmE48M15kzO3cfQAsHva5MPx0S0rHsVSYaD5vFiQdRKBIdEmZWcZK2rfXUHwVAloWQAjZaCQ=="
				}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("When invalid Content-Type is provided", func() {
			It("A HTTP Status: 415 response is received", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				// Create Request body
				createfReq := ``

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeXml)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("When a INVALID Report Create Request is passed", func() {
			It("Report is not created and HTTP Status: 400 response is received", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)

				createfReq := `{
					"instance_manifest": {
						"instance_info": {
							"instance_id": "bd06385a-5530-4644-a510-e384b8c3323a",
								"host_hardware_uuid": "00964993-89c1-e711-906e-00163566263e",
								"image_id": "773e22da-f687-47ca-89e7-5df655c60b7b"
				"trusted": true,
				"data": "eyJpbnN0YW5jZV9tYW5pZmVzdCI6eyJpbnN0YW5jZV9pbmZvIjp7Imluc3RhbmNlX2lkIjoiYmQwNjM4NWEtNTUzMC00NjQ0LWE1MTAtZTM4NGI4YzMzMjNhIiwiaG9zdF9oYXJkd2FyZV91dWlkIjoiMDA5NjQ5OTMtODljMS1lNzExLTkwNmUtMDAxNjM1NjYyNjNlIiwiaW1hZ2VfaWQiOiI3NzNlMjJkYS1mNjg3LTQ3Y2EtODllNy01ZGY2NTVjNjBiN2IifSwiaW1hZ2VfZW5jcnlwdGVkIjp0cnVlfSwicG9saWN5X25hbWUiOiJJbnRlbCBWTSBQb2xpY3kiLCJyZXN1bHRzIjpbeyJydWxlIjp7InJ1bGVfbmFtZSI6IkVuY3J5cHRpb25NYXRjaGVzIiwibWFya2VycyI6WyJJTUFHRSJdLCJleHBlY3RlZCI6eyJuYW1lIjoiZW5jcnlwdGlvbl9yZXF1aXJlZCIsInZhbHVlIjp0cnVlfX0sImZsYXZvcl9pZCI6IjNhM2UxY2NmLTI2MTgtNGEwZC04NDI2LWZiN2FjYjFlYmFiYyIsInRydXN0ZWQiOnRydWV9XSwidHJ1c3RlZCI6dHJ1ZX0=",
				"hash_alg": "SHA-256",
				"cert": "-----BEGIN CERTIFICATE-----\nMIIEkTCCA3mgAwIBAgIJAPZIe4/J1rS4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\nBAMTEG10d2lsc29uLXBjYS1haWswHhcNMTkwNDMwMDM0MjI3WhcNMjkwNDI3MDM0\nMjI3WjAlMSMwIQYDVQQDDBpDTj1TaWduaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJHAH8O1VLhSIxy3pa5MUemtrJQw\nONd3+JzO6wq5hRYf5iBOK1ADbAF0iLjGV0CXWYNVIQgCahqmn5TQGGFjsLZ4XpDy\nUmCkYsMzqZxcjGZr/dgmXci50v9o2m7FoQgt1eo6JEcB3NYwCkEHzEkx0Ns6cFul\nx9wsYUgU0CwRt2lderLJFs8O5ojKuID+6+bfJM+mGNmGfMudFDsSyJbw8uVqJN/w\njQNGhFIpapLabxcPrhwlUAf5efjldeKgoP/QFdOBolRT3R5HiCc4A28EwR+KpCsz\n2SnPtI7rJHiPZlsNYncroXSKkB2S7EXiFEnd0uME6Mhicg0dZ0U+yC+vEA8CAwEA\nAaOCAcwwggHIMA4GA1UdDwEB/wQEAwIGwDCBnQYHVQSBBQMCKQSBkf9UQ0eAFwAi\nAAvMr4Y5+2EueRqQYi93bUkUj0N+bRncFS9UlxfZLDbcpwAEAP9VqgAAAAAAFALJ\nAAAABQAAAAABAAcAKAAIMgAAIgALTGEwky4u3fkb0E2zIcrc6ernZN3qq3Ma4658\n19uM8tkAIgAL9bsq9DzOiSKNpNm6DNfh9SmdEZvY8cpOW+G/Ue0DLbswggEUBghV\nBIEFAwIpAQSCAQYAFAALAQCFbPimpFjbGCJ6+psrVrxu2vqY631OYyLg8xGaDdAh\nY2SEaZUub93Jp/UfmZt3bP2inG4kKhvmKAiIHHlRf+aFCZ7SJMNGrh9o6TwmVaiz\nT35YVjZpO6xFEmdv5eQIxYKCmE301QwHrvymqW+TeCPe8BWRtCcXA2Vuskf18xI9\nVafYJUSHC9NSk85538AbztXgJidOUgARpTweDJt8u3v2lkpZlhRk3+7kOkyI3xv+\nvvKeWaQokfkJiCWTCNT7vSVc14YKs4o4bXnYiwzpFtHuypMcBtcliDh12xnowGHs\nx7helzw/ue1ACQRHHhDuPDY1VECmuN/qUNRXunWrJTvXMA0GCSqGSIb3DQEBCwUA\nA4IBAQADtwxXKk6PaXKB1iFSyUAY4IQF3296xcYddGy6XxyLZH+ePkr/xmzBPbSW\nlzYgnDaJ+bohzJqio+abm1ovRahlEgCHLZatHvIcWbBqFpLgMw1Z2xTulcwuGtW/\nOSMKM/LfU1T8dyDisXojTsby2Rxj2wsfWC3GXrPWOkefkEC4qVyo7VXOVuAxZhPw\ni3ysiWPjTDnEHAJVqCtqsWSZHSwcpDeRnntMQ8GV6K+4TCZ6rcD9a47ArlvCKKoI\nNKFXK5xW8/xwaVikyMBAqlXjjWnS4HcIh7BYTj55Dxy9qjJJDBfqgXi7t8t7no2F\nBZRD/3W7YmEExAsSvX8Y4naY4rpU\n-----END CERTIFICATE-----\n",
				"signature": "KcC6UI6C5vLDrBIQx/EU9ceNPJDP6fjrF7F+6pxJYoA50rwx7ZI0ULbL2HXQiD82oQltqzj/n0KzY8JxY0PhIuG1w2vF58xOOzlxFP4w3BF6PSMW7wggwr1sj0TvlLcoyO7jXiK4nIlNfOqj6VaS/ynzMDGSSZvYkQ46SvAVdd0k57jHNG4TBrlqW+PWrM3xsqUrUeSVWCTH13G7qk6P4yPBnSerbmMBT4zuiodL+B0FsSlXorE6bZ/zt2N836DtL42eIbc7YXigLtvmE48M15kzO3cfQAsHva5MPx0S0rHsVSYaD5vFiQdRKBIdEmZWcZK2rfXUHwVAloWQAjZaCQ=="
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/reports"
	Describe("Search Report", func() {
		Context("When no filter arguments are passed", func() {
			It("All Report records are returned and a 200 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

			})
		})

		Context("When filtered by Report id", func() {
			It("Should get a single Report entry and a 200 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?id=f1c45b32-53cb-4982-9962-b04724f86b21", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var rCollection []model.Report
				err = json.Unmarshal(w.Body.Bytes(), &rCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(rCollection)).To(Equal(1))
			})
		})

		Context("When invalid report id format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?id=xc45b32-53cb-4982-9962-b04724f86b21", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by Hardware uuid", func() {
			It("Should get Report and a 200 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?hostHardwareId=00964993-89c1-e711-906e-00163566263e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var rCollection []model.Report
				err = json.Unmarshal(w.Body.Bytes(), &rCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(rCollection)).To(Equal(1))
			})
		})

		Context("When invalid hardware uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?hostHardwareId=xyz993-89c1-e711-906e-00163566263e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by Instance ID ", func() {
			It("Should get Report and a 200 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?instanceId=bd06385a-5530-4644-a510-e384b8c3323a", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var rCollection []model.Report
				err = json.Unmarshal(w.Body.Bytes(), &rCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(rCollection)).To(Equal(1))
			})
		})

		Context("When invalid instance id format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?instanceId=x-5530-4644-a510-e384b8c3323a", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by NumberOfDays ", func() {
			It("Should get Report and a 200 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?numberOfDays=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var rCollection []model.Report
				err = json.Unmarshal(w.Body.Bytes(), &rCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(rCollection)).To(Equal(1))
			})
		})

		Context("When negative numberOfDays is provided", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?numberOfDays=-111", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by FromDate and ToDate ", func() {
			It("Should get Report and a 200 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?fromDate=2021-06-01&toDate=2021-06-24", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var rCollection []model.Report
				err = json.Unmarshal(w.Body.Bytes(), &rCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(rCollection)).To(Equal(1))
			})
		})

		Context("When invalid Date format is provided", func() {
			It("Should not get Report and a 400 response code", func() {
				router.Handle("/reports", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?fromDate=202122-06-01&toDate=2021221-0612-24", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})

	// Specs for HTTP DELETE to "/report/{report_id}"
	Describe("Delete Report by ID", func() {
		Context("Delete Report by ID from data store", func() {
			It("Should delete Report and return a 204 response code", func() {
				router.Handle("/reports/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(reportController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/reports/f1c45b32-53cb-4982-9962-b04724f86b21", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("Delete Report by incorrect ID from data store", func() {
			It("Should fail to delete Report and return a 404 response code", func() {
				router.Handle("/reports/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(reportController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/reports/cf197a51-8362-465f-9ec1-d88ad0023a27", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Retrieve to "/report/{report_id}"
	Describe("Retrieve Report by ID", func() {
		Context("Retrieve Report by ID from data store", func() {
			It("Should Retrieve Report and return a 200 response code", func() {
				router.Handle("/reports/{id}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports/f1c45b32-53cb-4982-9962-b04724f86b21", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve Report by incorrect ID from data store", func() {
			It("Should fail to Retrieve Report and return a 404 response code", func() {
				router.Handle("/reports/{id}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(reportController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports/cf197a51-8362-465f-9ec1-d88ad0023a27", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
})
