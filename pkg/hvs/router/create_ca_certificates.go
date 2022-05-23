/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"net/http"
)

func SetCreateCaCertificatesRoutes(router *mux.Router, certStore *crypt.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/create_ca_certificates:SetCreateCaCertificatesRoutes() Entering")
	defer defaultLog.Trace("router/create_ca_certificates:SetCreateCaCertificatesRoutes() Leaving")

	caCertController := controllers.CaCertificatesController{CertStore: certStore}

	router.Handle("/ca-certificates",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(caCertController.Create),
			[]string{constants.CaCertificatesCreate}))).Methods(http.MethodPost)
	return router
}
