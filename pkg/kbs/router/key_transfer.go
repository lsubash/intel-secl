/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/directory"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
)

//setKeyTransferRoutes registers routes to perform Key transfer operation
func setKeyTransferRoutes(router *mux.Router, endpointUrl string, config domain.KeyTransferControllerConfig, keyManager keymanager.KeyManager, apsClient aps.APSClient, aasClient *aas.Client) *mux.Router {
	defaultLog.Trace("router/key_transfer:setKeyTransferRoutes() Entering")
	defer defaultLog.Trace("router/key_transfer:setKeyTransferRoutes() Leaving")

	keyStore := directory.NewKeyStore(constants.KeysDir)
	policyStore := directory.NewKeyTransferPolicyStore(constants.KeysTransferPolicyDir)
	remoteManager := keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)
	keyTransferController := controllers.NewKeyTransferController(remoteManager, policyStore, config, apsClient, aasClient)
	keyIdExpr := "/keys/" + validation.IdReg

	// For the below handlers Accept type needs to be explicitly added, otherwise the key transfer api requests for header with accept application/octet-stream
	// will be handled by JsonResponseHandler as per the order and respond with 415 status code.
	router.Handle(keyIdExpr+"/transfer",
		ErrorHandler(JsonResponseHandler(keyTransferController.Transfer))).Methods("POST").Headers("Accept", consts.HTTPMediaTypeJson)

	router.Handle(keyIdExpr+"/transfer",
		ErrorHandler(ResponseHandler(keyTransferController.TransferWithSaml))).Methods("POST").Headers("Accept", consts.HTTPMediaTypeOctetStream)

	return router
}
