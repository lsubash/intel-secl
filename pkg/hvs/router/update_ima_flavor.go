/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/postgres"
)

// SetImaFlavorRoutes registers routes for ima flavor
func SetImaFlavorRoutes(router *mux.Router, store *postgres.DataStore, flavorControllerConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/update_ima_flavor:SetImaFlavorRoutes() Entering")
	defer defaultLog.Trace("router/update_ima_flavor:SetImaFlavorRoutes() Leaving")

	hostStore := postgres.NewHostStore(store)
	imaController := controllers.NewImaController(hostStore, flavorControllerConfig)

	router.Handle("/update-ima-measurements",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(imaController.UpdateImaMeasurements),
			[]string{constants.ImaFlavorUpdate}))).
		Methods("POST")

	return router
}
