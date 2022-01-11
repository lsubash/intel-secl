/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/controllers"
	"net/http"
)

func InitRoutes(hubPublicKeys map[string][]byte, tagPrefix string) *mux.Router {
	router := mux.NewRouter()

	// handle basic get request
	router.HandleFunc("/", controllers.VersionController{}.GetVersion).Methods(http.MethodGet)

	// initialize the filter handler
	resourceStore := controllers.ResourceStore{
		IHubPubKeys: hubPublicKeys,
		TagPrefix:   tagPrefix,
	}
	filterHandler := controllers.FilterHandler{ResourceStore: resourceStore}

	//handler for the post operation
	router.HandleFunc("/filter", filterHandler.Filter).Methods(http.MethodPost)

	return router
}
