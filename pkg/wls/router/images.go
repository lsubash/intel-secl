/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
)

// SetImageRoutes registers routes for image
func SetImageRoutes(router *mux.Router, store *postgres.DataStore, conf *config.Configuration, certStore *models.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/flavors:SetFlavorRoutes() Entering")
	defer defaultLog.Trace("router/flavors:SetFlavorRoutes() Leaving")

	imageStore := postgres.NewImageStore(store)
	flavorStore := postgres.NewFlavorStore(store)

	imageController := controllers.NewImageController(imageStore, flavorStore, conf, certStore)

	imageIdExpr := fmt.Sprintf("%s%s", "/images/", validation.IdReg)
	flavorsExpr := fmt.Sprintf("%s/flavors", imageIdExpr)
	flavorIdExpr := fmt.Sprintf("%s/{flavorID}", flavorsExpr)
	flavorKeyExpr := fmt.Sprintf("%s/flavor-key", imageIdExpr)

	router.Handle("/images",
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.Create),
			[]string{constants.ImagesCreate}))).
		Methods("POST")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(imageController.DeleteImageFlavorAssociation),
			[]string{constants.ImageFlavorsDelete}))).Methods("DELETE")

	router.Handle(imageIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(imageController.Delete),
			[]string{constants.ImagesDelete}))).Methods("DELETE")

	router.Handle(imageIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.Retrieve),
			[]string{constants.ImagesRetrieve}))).Methods("GET")

	router.Handle(flavorsExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.RetrieveFlavorForFlavorPart),
			[]string{constants.ImageFlavorsRetrieve}))).Methods("GET").Queries("flavor_part", "{flavor_part}")

	router.Handle(flavorKeyExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.RetrieveFlavorAndKey),
			[]string{constants.ImageFlavorsRetrieve}))).Methods("GET").Queries("hardware_uuid", "{hardware_uuid}")

	router.Handle("/images",
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.Search),
			[]string{constants.ImagesSearch}))).Methods("GET")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(imageController.UpdateAssociatedFlavor),
			[]string{constants.ImageFlavorsStore}))).Methods("PUT")

	router.Handle(flavorsExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.GetAllAssociatedFlavors),
			[]string{constants.ImageFlavorsSearch}))).Methods("GET")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(imageController.GetAssociatedFlavor),
			[]string{constants.ImageFlavorsRetrieve}))).Methods("GET")

	return router
}
