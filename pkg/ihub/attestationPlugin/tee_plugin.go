/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package attestationPlugin

import (
	"github.com/intel-secl/intel-secl/v5/pkg/clients/fds"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	fdsModel "github.com/intel-secl/intel-secl/v5/pkg/model/fds"
	"net/url"

	"github.com/pkg/errors"
)

var FDSClient fds.Client

// FDSHost Registered host details on FDS
type FDSHost []struct {
	ConnectionString string `json:"connection_string"`
	HostID           string `json:"host_ID"`
	HostName         string `json:"host_name"`
	UUID             string `json:"uuid"`
}

// Retrieve platform data from FDS
func GetHostPlatformData(hostName string, config *config.Configuration, certDirectory string) ([]byte, error) {
	log.Trace("attestationPlugin/tee_plugin:GetHostPlatformData() Entering")
	defer log.Trace("attestationPlugin/tee_plugin:GetHostPlatformData() Leaving")

	fdsClient, err := initializeFDSClient(config, certDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/tee_plugin:GetHostPlatformData() Error in initialising FDS Client")
	}

	platformData, err := fdsClient.SearchHosts(&fdsModel.HostFilterCriteria{HostName: hostName})
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/tee_plugin:GetHostPlatformData() Error in getting platform details from FDS")
	}

	return platformData, nil
}

// initializeFDSClient method used to initialize the client
func initializeFDSClient(con *config.Configuration, certDirectory string) (fds.Client, error) {
	log.Trace("attestationPlugin/tee_plugin:initializeFDSClient() Entering")
	defer log.Trace("attestationPlugin/tee_plugin:initializeFDSClient() Leaving")

	if len(CertArray) < 0 && certDirectory != "" {
		err := loadCertificates(certDirectory)
		if err != nil {
			return nil, errors.Wrap(err, "attestationPlugin/tee_plugin:initializeFDSClient() Error in initializing certificates")
		}
	}

	aasURL, err := url.Parse(con.AASBaseUrl)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/tee_plugin:initializeFDSClient() Error parsing AAS URL")
	}

	attestationURL, err := url.Parse(con.AttestationService.FDSBaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/tee_plugin:initializeFDSClient() Error in parsing SGX Host Verification Service URL")
	}

	FDSClient = fds.NewClient(attestationURL, aasURL, CertArray, con.IHUB.Username, con.IHUB.Password)

	return FDSClient, nil
}
