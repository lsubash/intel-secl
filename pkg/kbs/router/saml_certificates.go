/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/directory"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"net/http"
)

//setSamlCertRoutes registers routes to perform SamlCertificate CRUD operations
func setSamlCertRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/saml_certificates:setSamlCertRoutes() Entering")
	defer defaultLog.Trace("router/saml_certificates:setSamlCertRoutes() Leaving")

	certStore := directory.NewCertificateStore(constants.SamlCertsDir)
	samlCertController := controllers.NewCertificateController(certStore)
	certIdExpr := "/saml-certificates/" + validation.IdReg

	router.Handle("/saml-certificates", ErrorHandler(permissionsHandler(JsonResponseHandler(samlCertController.Import),
		[]string{constants.SamlCertCreate}))).Methods(http.MethodPost)

	router.Handle(certIdExpr, ErrorHandler(permissionsHandler(JsonResponseHandler(samlCertController.Retrieve),
		[]string{constants.SamlCertRetrieve}))).Methods(http.MethodGet)

	router.Handle(certIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(samlCertController.Delete),
		[]string{constants.SamlCertDelete}))).Methods(http.MethodDelete)

	router.Handle("/saml-certificates", ErrorHandler(permissionsHandler(JsonResponseHandler(samlCertController.Search),
		[]string{constants.SamlCertSearch}))).Methods(http.MethodGet)

	return router
}
