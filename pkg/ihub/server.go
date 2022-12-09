/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ihub

import (
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/k8s"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/intel-secl/intel-secl/v5/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/k8splugin"
	"github.com/pkg/errors"

	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (app *App) startDaemon() error {

	log.Trace("startService:startDaemon() Entering")
	defer log.Trace("startService:startDaemon() Leaving")

	configuration := app.configuration()
	if configuration == nil {
		return errors.New("Failed to load configuration")
	}
	app.configureLogs(configuration.Log.EnableStdout, true)

	if configuration.PollIntervalMinutes < constants.PollingIntervalMinutes {
		secLog.Infof("startService:startDaemon() POLL_INTERVAL_MINUTES value is less than %v mins. Setting it to "+
			"%v mins", constants.PollingIntervalMinutes, constants.PollingIntervalMinutes)
		configuration.PollIntervalMinutes = constants.PollingIntervalMinutes
	}

	var k k8splugin.KubernetesDetails

	attestationHVSURL := configuration.AttestationService.HVSBaseURL
	attestationSHVSURL := configuration.AttestationService.SHVSBaseURL

	if attestationHVSURL == "" && attestationSHVSURL == "" {
		return errors.New("startService:startDaemon() Neither HVS nor SHVS Attestation URL are defined")
	}

	if configuration.Endpoint.Type == constants.K8sTenant {

		privateKey, err := crypt.GetPrivateKeyFromPKCS8File(app.configDir() + constants.PrivateKeyLocation)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() Error in reading the ihub private key from file")
		}
		k.PrivateKey = privateKey

		publicKeyBytes, err := ioutil.ReadFile(app.configDir() + constants.PublicKeyLocation)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() : Error in reading the ihub public key from file")
		}

		block, _ := pem.Decode(publicKeyBytes)
		if block == nil || block.Type != "PUBLIC KEY" {
			return errors.New("startService:startDaemon() : Error while decoding ihub certificate in pem format")
		}
		k.PublicKeyBytes = block.Bytes

		k.Config = configuration
		apiURL := k.Config.Endpoint.URL
		token := k.Config.Endpoint.Token
		certFile := k.Config.Endpoint.CertFile

		apiUrl, err := url.Parse(apiURL)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() Unable to parse Kubernetes api url")
		}

		k8sClient, err := k8s.NewK8sClient(apiUrl, token, certFile)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() Error in initializing the Kubernetes client")
		}
		k.K8sClient = k8sClient

		k.TrustedCAsStoreDir = app.configDir() + constants.TrustedCAsStoreDir
		if _, err := os.Stat(k.TrustedCAsStoreDir); err != nil {
			return errors.Wrap(err, "startService:startDaemon(): TrustedCA Certificate Missing, Error in initializing the Kubernetes client")
		}

		if attestationHVSURL != "" {
			k.SamlCertFilePath = app.configDir() + constants.SamlCertFilePath
			if _, err := os.Stat(k.SamlCertFilePath); err != nil {
				return errors.Wrap(err, "startService:startDaemon(): Saml Certificate Missing, Error in initializing the Kubernetes client")
			}
		}
	} else {
		return errors.Errorf("startService:startDaemon() Endpoint type '%s' is not supported", configuration.Endpoint.Type)
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// invoke for the first time before scheduling regular runs
	app.kickOffPlugins(k)

	tick := time.NewTicker(time.Minute * time.Duration(configuration.PollIntervalMinutes))
	go func() {
		secLog.Infof("startService:startDaemon() Scheduler will start at : %v", time.Now().Local().Add(
			time.Minute*time.Duration(configuration.PollIntervalMinutes)))
		for t := range tick.C {
			secLog.Debugf("startService:startDaemon() Scheduler started at : %v", t)
			app.kickOffPlugins(k)
		}
	}()

	secLog.Info(commLogMsg.ServiceStart)

	<-stop
	tick.Stop()

	secLog.Info(commLogMsg.ServiceStop)
	return nil
}

func (app *App) kickOffPlugins(k k8splugin.KubernetesDetails) {

	log.Debugf("startService:kickOffPlugins() The Endpoint is : %s", app.Config.Endpoint.Type)

	if app.Config.Endpoint.Type == constants.K8sTenant {
		err := k8splugin.SendDataToEndPoint(k)
		if err != nil {
			log.WithError(err).Error("startService:kickOffPlugins() : Error in pushing Kubernetes CRDs")
		}
	}
}
