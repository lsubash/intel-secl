/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
)

type DownloadSamlCaCert struct {
	HvsApiUrl         string
	ConsoleWriter     io.Writer
	SamlCertPath      string
	TrustedCaCertsDir string
	BearerToken       string
}

func (dc DownloadSamlCaCert) Run() error {
	log.Trace("tasks/download_saml_ca_cert:Run() Entering")
	defer log.Trace("tasks/download_saml_ca_cert:Run() Leaving")

	log.Info("tasks/download_saml_ca_cert:Run() Downloading SAML CA certificates.")
	if dc.BearerToken == "" {
		fmt.Fprintln(os.Stderr, "BEARER_TOKEN is not defined in environment")
		return errors.New("BEARER_TOKEN is not defined in environment")
	}

	vsClientFactory, err := hvsclient.NewVSClientFactory(dc.HvsApiUrl, dc.BearerToken, dc.TrustedCaCertsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tasks/download_saml_ca_cert:Run() Error while instantiating VSClientFactory")
		return errors.Wrap(err, "tasks/download_saml_ca_cert:Run() Error while instantiating VSClientFactory")
	}

	caCertsClient, err := vsClientFactory.CACertificatesClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tasks/download_saml_ca_cert:Run() Error while getting CACertificatesClient")
		return errors.Wrap(err, "tasks/download_saml_ca_cert:Run() Error while getting CACertificatesClient")
	}

	cacerts, err := caCertsClient.GetCaCertsInPem("saml")
	if err != nil {
		log.Error("tasks/download_saml_ca_cert:Run() Failed to read HVS response body for GET SAML ca-certificates API")
		return errors.Wrap(err, "tasks/download_saml_ca_cert:Run() Error while getting SAML CA certificates")
	}

	//write the output to a file
	err = ioutil.WriteFile(constants.SamlCaCertFilePath, cacerts, 0644)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_saml_ca_cert:Run() Error while writing file:%s", constants.SamlCaCertFilePath)
	}
	return nil
}

func (dc DownloadSamlCaCert) Validate() error {
	log.Trace("tasks/download_saml_ca_cert:Validate() Entering")
	defer log.Trace("tasks/download_saml_ca_cert:Validate() Leaving")

	log.Info("tasks/download_saml_ca_cert:Validate() Validation for downloading SAML CA certificates from HVS.")

	if _, err := os.Stat(constants.SamlCaCertFilePath); os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/download_saml_ca_cert:Validate() HVS SAML CA cert does not exist")
	}

	return nil
}

func (dc DownloadSamlCaCert) PrintHelp(w io.Writer) {
	var envHelp = map[string]string{
		"ATTESTATION_TYPE":        "Type of Attestation Service",
		"ATTESTATION_SERVICE_URL": "Base URL for the Attestation Service",
	}
	setup.PrintEnvHelp(w, "Following environment variables are required for download-saml-cert:", "", envHelp)
	fmt.Fprintln(w, "")
}

func (dc DownloadSamlCaCert) SetName(n, e string) {}
