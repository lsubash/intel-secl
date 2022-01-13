/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	wlsRoutes "github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("VersionController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var versionController *controllers.VersionController
	BeforeEach(func() {
		router = mux.NewRouter()
		versionController = &controllers.VersionController{}
	})

	// Specs for HTTP Get to "/version"
	Describe("Get Version", func() {
		Context("Get version details", func() {
			It("Should return version", func() {
				router.Handle("/version", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(versionController.GetVersion))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/version", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var version string
				version = string(w.Body.Bytes())
				Expect(version).NotTo(Equal(""))
			})
		})
	})

})
