/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
)

// SetFlavorRoutes registers routes for flavors
func SetFlavorRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/flavors:SetFlavorRoutes() Entering")
	defer defaultLog.Trace("router/flavors:SetFlavorRoutes() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	flavorController := controllers.NewFlavorController(flavorStore)

	flavorIdExpr := fmt.Sprintf("%s%s", "/flavors/", validation.IdReg)

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Create),
			[]string{constants.FlavorsCreate}))).
		Methods("POST")

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Search),
			[]string{constants.FlavorsSearch}))).Methods("GET")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(flavorController.Delete),
			[]string{constants.FlavorsDelete}))).Methods("DELETE")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(flavorController.Retrieve),
			[]string{constants.FlavorsRetrieve}))).Methods("GET")

	return router
}
