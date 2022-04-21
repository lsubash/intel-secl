/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/cms/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/cms/controllers"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// SetCACertificatesRoutes is used to set the endpoints for CA certificate handling APIs
func SetCACertificatesRoutes(router *mux.Router) *mux.Router {
	log.Trace("router/ca_certificates:SetCACertificatesRoutes() Entering")
	defer log.Trace("router/ca_certificates:SetCACertificatesRoutes() Leaving")
	caCertController := controllers.CACertificatesController{CaAttribs: constants.CertStoreMap}
	router.HandleFunc("/ca-certificates", caCertController.GetCACertificates).Methods(http.MethodGet)
	return router
}
