/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	cmw "github.com/intel-secl/intel-secl/v5/pkg/lib/common/middleware"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type Router struct {
	aasClient *aas.Client
}

// InitRoutes registers all routes for the application.
func InitRoutes(cfg *config.Configuration, keyTransferConfig domain.KeyTransferControllerConfig, keyManager keymanager.KeyManager, aasClient *aas.Client) *mux.Router {
	defaultLog.Trace("router/router:InitRoutes() Entering")
	defer defaultLog.Trace("router/router:InitRoutes() Leaving")

	// Create public routes that does not need any authentication
	router := mux.NewRouter()

	// ISECL-8715 - Prevent potential open redirects to external URLs
	router.SkipClean(true)

	// Define sub routes for path /kbs/v1
	defineSubRoutes(router, "/"+strings.ToLower(constants.ServiceName)+constants.ApiVersion, cfg, keyTransferConfig, keyManager, aasClient)

	return router
}

func defineSubRoutes(router *mux.Router, serviceApi string, cfg *config.Configuration, keyTransferConfig domain.KeyTransferControllerConfig, keyManager keymanager.KeyManager, aasClient *aas.Client) {
	defaultLog.Trace("router/router:defineSubRoutes() Entering")
	defer defaultLog.Trace("router/router:defineSubRoutes() Leaving")

	subRouter := router.PathPrefix(serviceApi).Subrouter()
	subRouter = setVersionRoutes(subRouter)
	subRouter = setKeyTransferRoutes(subRouter, cfg.EndpointURL, keyTransferConfig, keyManager)
	subRouter = router.PathPrefix(serviceApi).Subrouter()
	cfgRouter := Router{aasClient: aasClient}
	var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)

	subRouter.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir,
		constants.TrustedCaCertsDir, cfgRouter.fnGetJwtCerts,
		cacheTime))
	subRouter = setKeyRoutes(subRouter, cfg.EndpointURL, keyTransferConfig.DefaultTransferPolicyId, keyManager)
	subRouter = setKeyTransferPolicyRoutes(subRouter)
	subRouter = setSamlCertRoutes(subRouter)
	subRouter = setTpmIdentityCertRoutes(subRouter)
}

// Fetch JWT certificate from AAS
func (router *Router) fnGetJwtCerts() error {
	defaultLog.Trace("router/router:fnGetJwtCerts() Entering")
	defer defaultLog.Trace("router/router:fnGetJwtCerts() Leaving")

	jwtCert, err := router.aasClient.GetJwtSigningCertificate()
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Error retrieving JWT signing certificate from AAS")
	}

	err = crypt.SavePemCertWithShortSha1FileName(jwtCert, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not store Certificate")
	}
	return nil
}
