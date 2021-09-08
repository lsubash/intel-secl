/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/directory"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
)

//setKeyTransferRoutes registers routes to perform Key transfer operation
func setKeyTransferRoutes(router *mux.Router, endpointUrl string, config domain.KeyControllerConfig, keyManager keymanager.KeyManager, apsClient aps.APSClient) *mux.Router {
	defaultLog.Trace("router/key_transfer:setKeyTransferRoutes() Entering")
	defer defaultLog.Trace("router/key_transfer:setKeyTransferRoutes() Leaving")

	keyStore := directory.NewKeyStore(constants.KeysDir)
	policyStore := directory.NewKeyTransferPolicyStore(constants.KeysTransferPolicyDir)
	remoteManager := keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)
	keyTransferController := controllers.NewKeyTransferController(remoteManager, policyStore, config, apsClient)
	keyIdExpr := "/keys/" + validation.IdReg

	router.Handle(keyIdExpr+"/transfer",
		ErrorHandler(JsonResponseHandler(keyTransferController.Transfer))).Methods("POST")

	return router
}
