/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/authservice/controllers"
	"net/http"
)

func SetJwtCertificateRoutes(r *mux.Router) *mux.Router {
	defaultLog.Trace("router/jwt_certificate:SetJwtCertificateRoutes() Entering")
	defer defaultLog.Trace("router/jwt_certificate:SetJwtCertificateRoutes() Leaving")

	controller := controllers.JwtCertificateController{}
	r.Handle("/jwt-certificates", ErrorHandler(ResponseHandler(controller.GetJwtCertificate, "application/x-pem-file"))).Methods(http.MethodGet)
	return r
}
