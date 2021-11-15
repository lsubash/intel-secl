/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/directory"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"net/http"
)

//setKeyRoutes registers routes to perform Key CRUD operations
func setKeyRoutes(router *mux.Router, endpointUrl string, defaultPolicyId uuid.UUID, keyManager keymanager.KeyManager) *mux.Router {
	defaultLog.Trace("router/keys:setKeyRoutes() Entering")
	defer defaultLog.Trace("router/keys:setKeyRoutes() Leaving")

	keyStore := directory.NewKeyStore(constants.KeysDir)
	policyStore := directory.NewKeyTransferPolicyStore(constants.KeysTransferPolicyDir)
	remoteManager := keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)
	keyController := controllers.NewKeyController(remoteManager, policyStore, defaultPolicyId)
	keyIdExpr := "/keys/" + validation.IdReg

	router.Handle("/keys",
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Create),
			[]string{constants.KeyCreate, constants.KeyRegister}))).Methods(http.MethodPost)

	router.Handle(keyIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Retrieve),
			[]string{constants.KeyRetrieve}))).Methods(http.MethodGet)

	router.Handle(keyIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Delete),
			[]string{constants.KeyDelete}))).Methods(http.MethodDelete)

	router.Handle("/keys",
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Search),
			[]string{constants.KeySearch}))).Methods(http.MethodGet)

	router.Handle(keyIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Transfer),
			[]string{constants.KeyTransfer}))).Methods(http.MethodPost)

	return router
}
