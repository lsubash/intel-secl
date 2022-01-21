/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/vs"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
)

type DownloadSamlCaCert struct {
	HvsApiUrl         string
	ConsoleWriter     io.Writer
	SamlCertPath      string
	TrustedCaCertsDir string
}

func (dc DownloadSamlCaCert) Run() error {
	log.Trace("tasks/download_saml_ca_cert:Run() Entering")
	defer log.Trace("tasks/download_saml_ca_cert:Run() Leaving")

	hvsUrl := dc.HvsApiUrl
	if hvsUrl == "" {
		fmt.Fprintln(dc.ConsoleWriter, "tasks/download_saml_cert:Run() HVS_URL is not set")
		return nil
	}

	if !strings.HasSuffix(hvsUrl, "/") {
		hvsUrl = hvsUrl + "/"
	}

	baseURL, err := url.Parse(hvsUrl)
	if err != nil {
		return errors.Wrap(err, "tasks/download_saml_cert:Run() Error in parsing Host Verification Service URL")
	}

	vsClient := &vs.Client{
		BaseURL: baseURL,
	}

	caCerts, err := vsClient.GetCaCerts("saml")
	if err != nil {
		return errors.Wrap(err, "tasks/download_saml_cert:Run() Failed to get SAML ca-certificates from HVS")
	}

	//write the output to a file
	err = ioutil.WriteFile(constants.SamlCaCertFilePath, caCerts, 0644)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_saml_ca_cert:Run() Error while writing file:%s", constants.SamlCaCertFilePath)
	}
	err = os.Chmod(constants.SamlCaCertFilePath, 0640)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_saml_cert:Run() Error while changing file permission for file :%s", constants.SamlCaCertFilePath)
	}
	return nil
}

func (dc DownloadSamlCaCert) Validate() error {
	log.Trace("tasks/download_saml_ca_cert:Validate() Entering")
	defer log.Trace("tasks/download_saml_ca_cert:Validate() Leaving")

	if _, err := os.Stat(constants.SamlCaCertFilePath); os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/download_saml_ca_cert:Validate() HVS SAML CA cert does not exist")
	}

	return nil
}

func (dc DownloadSamlCaCert) PrintHelp(w io.Writer) {
	var envHelp = map[string]string{
		"HVS_URL": "HVS Base URL",
	}
	setup.PrintEnvHelp(w, "Following environment variables are required for download-saml-cert:", "", envHelp)
	fmt.Fprintln(w, "")
}

func (dc DownloadSamlCaCert) SetName(n, e string) {}
