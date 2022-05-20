/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/authservice/controllers"
	aasRoutes "github.com/intel-secl/intel-secl/v5/pkg/authservice/router"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	tokenSignCertFile = "../../../test/aas/jwtsigncert.pem"
)

var _ = Describe("JwtCertificateController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	var jwtCertificateController controllers.JwtCertificateController

	jwtCertificateControllerTest := controllers.JwtCertificateController{
		TokenSignCertFile: "../../../test/aas/jwtsigncert1.pem",
	}

	BeforeEach(func() {
		router = mux.NewRouter()
		jwtCertificateController = controllers.JwtCertificateController{
			TokenSignCertFile: tokenSignCertFile,
		}
	})

	Describe("GetJwtCertificate", func() {
		Context("Validate Get JwtCertificate", func() {
			It("Should return StatusOK - Valid certificate provided", func() {
				router.Handle("/jwt-certificates", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtCertificateController.GetJwtCertificate, "application/x-pem-file"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/jwt-certificates", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})

			It("Should return InternalServerError - Invalid certificate location provided", func() {
				router.Handle("/jwt-certificates", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtCertificateControllerTest.GetJwtCertificate, "application/x-pem-file"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/jwt-certificates", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})
})
