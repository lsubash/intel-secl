/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/postgres"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
)

// SetFlavorRoutes registers routes for flavors
func SetFlavorRoutes(router *mux.Router, store *postgres.DataStore, flavorGroupStore *postgres.FlavorGroupStore, certStore *crypt.CertificatesStore, hostTrustManager domain.HostTrustManager, flavorControllerConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/flavors:SetFlavorRoutes() Entering")
	defer defaultLog.Trace("router/flavors:SetFlavorRoutes() Leaving")

	hostStore := postgres.NewHostStore(store)
	flavorStore := postgres.NewFlavorStore(store)
	tagCertStore := postgres.NewTagCertificateStore(store)
	flavorTemplateStore := postgres.NewFlavorTemplateStore(store)
	flavorController := controllers.NewFlavorController(flavorStore, flavorGroupStore, hostStore, tagCertStore, hostTrustManager, certStore, flavorControllerConfig, flavorTemplateStore)

	flavorIdExpr := fmt.Sprintf("%s%s", "/flavors/", validation.IdReg)

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Create),
			[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
		Methods(http.MethodPost)

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Search),
			[]string{constants.FlavorSearch}))).Methods(http.MethodGet)

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(flavorController.Delete),
			[]string{constants.FlavorDelete}))).Methods(http.MethodDelete)

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Retrieve),
			[]string{constants.FlavorRetrieve}))).Methods(http.MethodGet)

	return router
}
