/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package attestationPlugin

import (
	"net/url"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/fds"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	fdsModel "github.com/intel-secl/intel-secl/v5/pkg/model/fds"

	"github.com/pkg/errors"
)

var FDSClient fds.Client

// Retrieve platform data from FDS
func GetHostPlatformData(hostHardwareUUID uuid.UUID, config *config.Configuration, certDirectory string) ([]*fdsModel.Host, error) {
	log.Trace("attestationPlugin/tee_plugin:GetHostPlatformData() Entering")
	defer log.Trace("attestationPlugin/tee_plugin:GetHostPlatformData() Leaving")

	fdsClient, err := initializeFDSClient(config, certDirectory)
	if err != nil {
		return nil, errors.Wrap(err, "attestationPlugin/tee_plugin:GetHostPlatformData() Error in initialising FDS Client")
	}

	platformData, err := fdsClient.SearchHosts(&fdsModel.HostFilterCriteria{HardwareId: hostHardwareUUID})
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
		return nil, errors.Wrap(err, "attestationPlugin/tee_plugin:initializeFDSClient() Error in parsing FDS URL")
	}

	FDSClient = fds.NewClient(attestationURL, aasURL, CertArray, con.IHUB.Username, con.IHUB.Password)

	return FDSClient, nil
}
