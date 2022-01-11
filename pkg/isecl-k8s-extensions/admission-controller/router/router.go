/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/controllers"
	"net/http"
)

func InitRouter() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc(constants.MutateRoute, controllers.HandleMutate).Methods(http.MethodPost)

	return router
}
