/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/mocks"
	wlsRoutes "github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

var _ = Describe("KeyController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var keyController *controllers.KeyController

	BeforeEach(func() {
		router = mux.NewRouter()
		var conf config.Configuration
		conf.HVSApiUrl = "http://localhost:1338/mtwilson/v2/"
		conf.AASApiUrl = "http://localhost:1336/aas/v1/"
		conf.WLS.Username = "wls"
		conf.WLS.Password = "password"
		certStore := mocks.NewFakeCertificatesStore()
		keyController = controllers.NewKeyController(&conf, certStore)
	})

	Describe("Retrieve key", func() {
		Context("A valid retrieve key request", func() {
			It("A HTTP Status: 400 response is received", func() {
				k := mockKBS(":1337")
				defer k.Close()
				h := mockHVS(":1338")
				defer h.Close()
				a := mockAAS(":1336")
				defer a.Close()
				time.Sleep(1 * time.Second)

				router.Handle("/keys", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(keyController.RetrieveKey))).Methods(http.MethodPost)
				createfReq := `{
					"hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
					"key_url": "http://localhost:1337/v1/keys/98cb8e99-389a-4fdc-a430-e5c0ab7d7a40/transfer"
				}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("When invalid hardware uuid format is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/keys", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(keyController.RetrieveKey))).Methods(http.MethodPost)
				createfReq := `{
					"hardware_uuid": "964vv-89C1-E711-906E-00163566263E",
					"key_url": "http://localhost:1337/v1/keys/eb61b2e9-c7cd-4476-ac5f-71582c892112/transfer"
				}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					strings.NewReader(createfReq),
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
