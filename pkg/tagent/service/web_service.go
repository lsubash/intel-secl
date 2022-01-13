/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/router"
	"github.com/pkg/errors"
	stdlog "log"
	"net/http"
	"os"
	"time"
)

type trustAgentWebService struct {
	webParameters WebParameters
	router        *mux.Router
	server        *http.Server
}

func (service *trustAgentWebService) Start() error {
	log.Trace("resource/service:Start() Entering")
	defer log.Trace("resource/service:Start() Leaving")

	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	httpWriter := os.Stderr
	if httpLogFile, err := os.OpenFile(constants.HttpLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err != nil {
		secLog.WithError(err).Errorf("resource/service:Start() %s Failed to open http log file: %s\n", message.AppRuntimeErr, err.Error())
		log.Tracef("resource/service:Start() %+v", err)
	} else {
		defer func() {
			derr := httpLogFile.Close()
			if derr != nil {
				log.WithError(derr).Warn("Error closing file")
			}
		}()
		httpWriter = httpLogFile
	}

	httpLog := stdlog.New(httpWriter, "", 0)
	service.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", service.webParameters.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(os.Stderr, service.router)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       service.webParameters.ReadTimeout,
		ReadHeaderTimeout: service.webParameters.ReadHeaderTimeout,
		WriteTimeout:      service.webParameters.WriteTimeout,
		IdleTimeout:       service.webParameters.IdleTimeout,
		MaxHeaderBytes:    service.webParameters.MaxHeaderBytes,
	}

	// dispatch web server go routine
	go func() {
		if err := service.server.ListenAndServeTLS(service.webParameters.TLSCertFilePath, service.webParameters.TLSKeyFilePath); err != nil {
			secLog.Errorf("tasks/service:Start() %s", message.TLSConnectFailed)
			secLog.WithError(err).Fatalf("server:startServer() Failed to start HTTPS server: %s\n", err.Error())
			log.Tracef("%+v", err)
		}
	}()
	secLog.Info(message.ServiceStart)
	secLog.Infof("TrustAgent service is running: %d", service.webParameters.Port)

	return nil
}

func (service *trustAgentWebService) Stop() error {
	if service.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.server.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to gracefully shutdown webserver: %v\n", err)
			log.WithError(err).Info("Failed to gracefully shutdown webserver")
			return err
		}
	}

	return nil
}

func newWebService(webParameters *WebParameters, requestHandler common.RequestHandler) (TrustAgentService, error) {
	log.Trace("service/web_service:newWebService() Entering")
	defer log.Trace("service/web_service:newWebService() Leaving")

	if webParameters.Port == 0 {
		return nil, errors.New("Port cannot be zero")
	}

	trustAgentService := trustAgentWebService{
		webParameters: *webParameters,
		router:        router.InitRoutes(webParameters.TrustedJWTSigningCertsDir, webParameters.TrustedCaCertsDir, requestHandler),
		server:        nil,
	}

	return &trustAgentService, nil
}
