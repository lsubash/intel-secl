/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	cmw "github.com/intel-secl/intel-secl/v5/pkg/lib/common/middleware"
	cos "github.com/intel-secl/intel-secl/v5/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type Router struct {
	cfg *config.Configuration
}

// InitRoutes registers all routes for the application.
func InitRoutes(cfg *config.Configuration, dataStore *postgres.DataStore, certStore *crypt.CertificatesStore) (*mux.Router, error) {
	defaultLog.Trace("router/router:InitRoutes() Entering")
	defer defaultLog.Trace("router/router:InitRoutes() Leaving")

	// Create public routes that does not need any authentication
	router := mux.NewRouter()

	router.SkipClean(true)
	err := defineSubRoutes(router, strings.ToLower(constants.ServiceName), cfg, dataStore, certStore)
	if err != nil {
		return nil, errors.Wrap(err, "Could not define sub routes")
	}
	err = defineSubRoutesV1(router, strings.ToLower(constants.ServiceName), cfg, dataStore, certStore)
	if err != nil {
		return nil, errors.Wrap(err, "Could not define sub routes")
	}
	return router, nil
}

func defineSubRoutes(router *mux.Router, service string, cfg *config.Configuration, dataStore *postgres.DataStore, certStore *crypt.CertificatesStore) error {
	defaultLog.Trace("router/router:defineSubRoutes() Entering")
	defer defaultLog.Trace("router/router:defineSubRoutes() Leaving")

	serviceApi := "/" + service + "/v{version:[1-2]}/"
	subRouter := router.PathPrefix(serviceApi).Subrouter()
	subRouter = SetVersionRoutes(subRouter)

	cfgRouter := Router{cfg: cfg}
	var cacheTime, err = time.ParseDuration(constants.JWTCertsCacheTime)
	if err != nil {
		return errors.Wrap(err, "Could not parse JWT Certificate cache time")
	}
	subRouter.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir,
		constants.TrustedCaCertsDir, cfgRouter.fnGetJwtCerts,
		cacheTime))
	subRouter = SetFlavorRoutes(subRouter, dataStore)
	subRouter = SetReportRoutes(subRouter, dataStore)
	subRouter = SetImageRoutes(subRouter, dataStore, cfg, certStore)
	subRouter = SetKeyRoutes(subRouter, cfg, certStore)
	return nil
}

func defineSubRoutesV1(router *mux.Router, service string, cfg *config.Configuration, dataStore *postgres.DataStore, certStore *crypt.CertificatesStore) error {
	defaultLog.Trace("router/router:defineSubRoutes() Entering")
	defer defaultLog.Trace("router/router:defineSubRoutes() Leaving")

	serviceApi := "/" + service + "/v1/"
	subRouter := router.PathPrefix(serviceApi).Subrouter()
	cfgRouter := Router{cfg: cfg}
	var cacheTime, err = time.ParseDuration(constants.JWTCertsCacheTime)
	if err != nil {
		return errors.Wrap(err, "Could not parse JWT Certificate cache time")
	}
	subRouter.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir,
		constants.TrustedCaCertsDir, cfgRouter.fnGetJwtCerts,
		cacheTime))

	subRouter = SetImageRoutesV1(subRouter, dataStore, cfg, certStore)
	return nil
}

// Fetch JWT certificate from AAS
//TODO: use interface to store save certificates
func (r *Router) fnGetJwtCerts() error {
	defaultLog.Trace("router/router:fnGetJwtCerts() Entering")
	defer defaultLog.Trace("router/router:fnGetJwtCerts() Leaving")

	cfg := r.cfg
	if !strings.HasSuffix(cfg.AASApiUrl, "/") {
		cfg.AASApiUrl = cfg.AASApiUrl + "/"
	}
	url := cfg.AASApiUrl + "jwt-certificates"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.TrustedCaCertsDir, "*.pem")
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not read root CA certificate")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Failed defining certificate pool")
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer func() {
		derr := res.Body.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing response body")
		}
	}()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Failed read response")
	}
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "router/router:fnGetJwtCerts() Could not store Certificate")
	}
	return nil
}
