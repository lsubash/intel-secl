/*
 *  Copyright (C) 2022 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"net/http"

	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/authservice/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/authservice/controllers"
)

func SetJwtCertificateRoutes(r *mux.Router) *mux.Router {
	defaultLog.Trace("router/jwt_certificate:SetJwtCertificateRoutes() Entering")
	defer defaultLog.Trace("router/jwt_certificate:SetJwtCertificateRoutes() Leaving")

	controller := controllers.JwtCertificateController{TokenSignCertFile: consts.TokenSignCertFile}
	r.Handle("/jwt-certificates", ErrorHandler(ResponseHandler(controller.GetJwtCertificate, "application/x-pem-file"))).Methods(http.MethodGet)
	return r
}
