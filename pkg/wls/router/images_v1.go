/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
	"net/http"
)

// SetImageRoutes registers routes for image
func SetImageRoutesV1(router *mux.Router, store *postgres.DataStore, conf *config.Configuration, certStore *crypt.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/flavors:SetFlavorRoutes() Entering")
	defer defaultLog.Trace("router/flavors:SetFlavorRoutes() Leaving")

	imageStore := postgres.NewImageStore(store)
	flavorStore := postgres.NewFlavorStore(store)

	imageController := controllers.NewImageController(imageStore, flavorStore, conf, certStore)

	imageIdExpr := fmt.Sprintf("%s%s", "/images/", validation.IdReg)
	flavorsExpr := fmt.Sprintf("%s/flavors", imageIdExpr)
	flavorIdExpr := fmt.Sprintf("%s/{flavorID}", flavorsExpr)

	router.Handle(flavorsExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.GetAllAssociatedFlavorsv1),
			[]string{constants.ImageFlavorsSearch}))).Methods(http.MethodGet)

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.GetAssociatedFlavorv1),
			[]string{constants.ImageFlavorsRetrieve}))).Methods(http.MethodGet)

	return router
}
