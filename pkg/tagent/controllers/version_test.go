/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/controllers"
	tagentRouter "github.com/intel-secl/intel-secl/v5/pkg/tagent/router"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetVersion Request", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	BeforeEach(func() {
		router = mux.NewRouter()
	})

	Describe("GetVersion", func() {
		Context("GetVersion request", func() {
			It("Should perform GetVersion", func() {

				router.HandleFunc("/v2/version", tagentRouter.ErrorHandler(controllers.GetVersion())).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/v2/version", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})
})
