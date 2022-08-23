/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v5/pkg/hvs/router"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	mocks2 "github.com/intel-secl/intel-secl/v5/pkg/lib/host-connector/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ImaController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var hostStore *mocks.MockHostStore
	var hostControllerConfig domain.HostControllerConfig
	var hostConnectorProvider mocks2.MockHostConnectorFactory
	var imaController *controllers.ImaController

	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()

		hostControllerConfig = domain.HostControllerConfig{
			HostConnectorProvider: hostConnectorProvider,
			DataEncryptionKey:     nil,
			Username:              "fakeuser",
			Password:              "fakepassword",
		}

		imaController = controllers.NewImaController(hostStore, hostControllerConfig)
	})

	Describe("Send ima file details to host", func() {

		Context("Provide a valid ima details", func() {
			It("Should send ima file details successfully", func() {
				router.Handle("/update-ima-measurements", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(imaController.UpdateImaMeasurements))).Methods(http.MethodPost)
				imaFlavorUpdateRequestJson := `{
					 "connection_string": "https://127.0.0.1:1443",
					 "files": [
						 "test1",
						 "test2"
					 ]
				 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/update-ima-measurements",
					strings.NewReader(imaFlavorUpdateRequestJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Provide an invalid content-type", func() {
			It("fail to send ima file details", func() {
				router.Handle("/update-ima-measurements", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(imaController.UpdateImaMeasurements))).Methods(http.MethodPost)
				imaFlavorUpdateRequestJson := `{
					 "connection_string": "https://127.0.0.1:1443",
					 "files": [
						 "test1",
						 "test2"
					 ]
				 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/update-ima-measurements",
					strings.NewReader(imaFlavorUpdateRequestJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeSaml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide an empty request", func() {
			It("fail to send ima file details", func() {
				router.Handle("/update-ima-measurements", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(imaController.UpdateImaMeasurements))).Methods(http.MethodPost)

				req, err := http.NewRequest(
					http.MethodPost,
					"/update-ima-measurements",
					strings.NewReader(""),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide an empty connection string", func() {
			It("fail to send ima file details", func() {
				router.Handle("/update-ima-measurements", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(imaController.UpdateImaMeasurements))).Methods(http.MethodPost)
				imaFlavorUpdateRequestJson := `{
						 "connection_string": "",
						 "files": [
							 "test1",
							 "test2"
						 ]
					 }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/update-ima-measurements",
					strings.NewReader(imaFlavorUpdateRequestJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
