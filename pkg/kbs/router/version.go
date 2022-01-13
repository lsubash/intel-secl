/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/controllers"
	"net/http"
)

func setVersionRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/version:setVersionRoutes() Entering")
	defer defaultLog.Trace("router/version:setVersionRoutes() Leaving")
	versionController := controllers.VersionController{}

	router.Handle("/version", ErrorHandler(ResponseHandler(versionController.GetVersion))).Methods(http.MethodGet)
	return router
}
