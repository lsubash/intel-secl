/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/intel-secl/intel-secl/v5/pkg/clients"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/keymanager"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/router"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/utils"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/pkg/errors"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (app *App) startServer() error {
	defaultLog.Trace("kbs/server:startServer() Entering")
	defer defaultLog.Trace("kbs/server:startServer() Leaving")

	configuration := app.configuration()
	if configuration == nil {
		return errors.New("kbs/server:startServer() Failed to load configuration")
	}
	// Initialize log
	if err := app.configureLogs(configuration.Log.EnableStdout, true); err != nil {
		return err
	}

	// Initialize KeyTransferControllerConfig
	kcc, err := initKeyTransferControllerConfig()
	if err != nil {
		return err
	}

	// Initialize KeyManager
	km, err := keymanager.NewKeyManager(configuration)
	if err != nil {
		return err
	}

	apsBaseUrl, err := url.Parse(configuration.APSBaseUrl)
	if err != nil {
		defaultLog.WithError(err).Error("kbs/server:startServer() Error parsing APS url")
		return err
	}

	//Load trusted CA certificates
	caCerts, err := crypt.GetCertsFromDir(constants.TrustedCaCertsDir)
	if err != nil {
		defaultLog.WithError(err).Error("kbs/server:startServer() Error loading CA certificates")
		return err
	}

	//Initialize the APS client
	apsClient := aps.NewAPSClient(apsBaseUrl, caCerts, configuration.CustomToken)

	client, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		defaultLog.WithError(err).Error("kbs/server:startServer() Error while creating http client")
		return err
	}

	//Initialize the AAS client
	aasClient := &aas.Client{
		BaseURL:    configuration.AASBaseUrl,
		JWTToken:   []byte(configuration.CustomToken),
		HTTPClient: client,
	}

	// Initialize routes
	routes := router.InitRoutes(configuration, kcc, km, apsClient, aasClient)

	defaultLog.Info("kbs/server:startServer() Starting server")
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		ClientAuth: tls.RequestClientCert,
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := log.New(app.httpLogWriter(), "", 0)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", configuration.Server.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(app.httpLogWriter(), routes)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsConfig,
		ReadTimeout:       configuration.Server.ReadTimeout,
		ReadHeaderTimeout: configuration.Server.ReadHeaderTimeout,
		WriteTimeout:      configuration.Server.WriteTimeout,
		IdleTimeout:       configuration.Server.IdleTimeout,
		MaxHeaderBytes:    configuration.Server.MaxHeaderBytes,
	}

	tlsCert := configuration.TLS.CertFile
	tlsKey := configuration.TLS.KeyFile
	// Dispatch web server go routine
	go func() {
		if err := httpServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			if err != http.ErrServerClosed {
				defaultLog.WithError(err).Fatal("Failed to start HTTPS server")
			}
			stop <- syscall.SIGTERM
		}
	}()

	secLog.Info(commLogMsg.ServiceStart)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		defaultLog.WithError(err).Error("kbs/server:startServer() Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(commLogMsg.ServiceStop)
	return nil
}

func initKeyTransferControllerConfig() (domain.KeyTransferControllerConfig, error) {
	defaultLog.Trace("kbs/server:initKeyTransferControllerConfig() Entering")
	defer defaultLog.Trace("kbs/server:initKeyTransferControllerConfig() Leaving")

	id, err := utils.GetDefaultKeyTransferPolicyId()
	if err != nil {
		return domain.KeyTransferControllerConfig{}, err
	}

	kcc := domain.KeyTransferControllerConfig{
		AasJwtSigningCertsDir:   constants.TrustedJWTSigningCertsDir,
		ApsJwtSigningCertsDir:   constants.ApsJWTSigningCertsDir,
		SamlCertsDir:            constants.SamlCertsDir,
		TrustedCaCertsDir:       constants.TrustedCaCertsDir,
		TpmIdentityCertsDir:     constants.TpmIdentityCertsDir,
		DefaultTransferPolicyId: id,
	}
	return kcc, nil
}
