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

// SetReportRoutes registers routes for reports
func SetReportRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/reports:SetReportRoutes() Entering")
	defer defaultLog.Trace("router/reports:SetReportRoutes() Leaving")

	reportStore := postgres.NewReportStore(store)
	reportController := controllers.NewReportController(reportStore)

	reportIdExpr := fmt.Sprintf("%s%s", "/reports/", validation.IdReg)

	router.Handle("/reports",
		ErrorHandler(permissionsHandler(JsonResponseHandler(reportController.Create),
			[]string{constants.ReportsCreate}))).Methods("POST")

	router.Handle(reportIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(reportController.Retrieve),
			[]string{constants.ReportsSearch}))).Methods("GET")

	router.Handle("/reports",
		ErrorHandler(permissionsHandler(JsonResponseHandler(reportController.Search),
			[]string{constants.ReportsSearch}))).Methods("GET")

	router.Handle(reportIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(reportController.Delete),
			[]string{constants.ReportsDelete}))).Methods("DELETE")

	return router
}
