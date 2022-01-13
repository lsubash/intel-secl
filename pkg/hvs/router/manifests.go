/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/postgres"
	"net/http"
)

//SetManifestsRoute registers routes for manifests api
func SetManifestsRoute(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/manifests:SetManifestsRoutes() Entering")
	defer defaultLog.Trace("router/manifests:SetManifestsRoutes() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	manifestsController := controllers.NewManifestsController(flavorStore)

	router.Handle("/manifests",
		ErrorHandler(permissionsHandler(XMLResponseHandler(manifestsController.GetManifest),
			[]string{constants.FlavorSearch}))).Methods(http.MethodGet)

	return router
}
