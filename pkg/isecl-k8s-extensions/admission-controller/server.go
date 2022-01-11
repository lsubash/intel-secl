/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package admission_controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/config"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/constants"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func StartServer(router *mux.Router, admissionControllerConfig config.Config) error {
	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGKILL)
	//get a webserver instance, that contains a muxer, middleware and configuration settings

	//initialize http server config
	httpWriter := os.Stderr
	if httpLogFile, err := os.OpenFile(constants.HttpLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
		defaultLog.Tracef("service:Start() %+v", err)
	} else {
		defer func() {
			derr := httpLogFile.Close()
			if derr != nil {
				defaultLog.WithError(derr).Error("Error closing file")
			}
		}()
		httpWriter = httpLogFile
	}

	httpLog := stdlog.New(httpWriter, "", 0)
	h := &http.Server{
		Addr:      fmt.Sprintf(":%d", admissionControllerConfig.Port),
		Handler:   handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(os.Stderr, router)),
		ErrorLog:  httpLog,
		TLSConfig: tlsconfig,
	}

	// dispatch web server go routine
	go func() {
		if err := h.ListenAndServeTLS(admissionControllerConfig.ServerCert, admissionControllerConfig.ServerKey); err != nil {
			defaultLog.Errorf("failed to start service %+v", err)
			stop <- syscall.SIGTERM
		}
	}()
	defaultLog.Info("Service started")

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to gracefully shutdown webserver: %v\n", err)
		return nil
	}

	return nil
}
