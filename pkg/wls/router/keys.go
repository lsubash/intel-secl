/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
)

// SetKeyRoutes registers routes for keys
func SetKeyRoutes(router *mux.Router, config *config.Configuration, certStore *models.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/reports:SetReportRoutes() Entering")
	defer defaultLog.Trace("router/reports:SetReportRoutes() Leaving")

	keyController := controllers.NewKeyController(config, certStore)

	router.Handle("/keys",
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.RetrieveKey),
			[]string{constants.KeysCreate}))).Methods("POST")

	return router
}
