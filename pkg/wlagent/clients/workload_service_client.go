/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package clients

import (
	"github.com/intel-secl/intel-secl/v5/pkg/clients/wlsclient"
	wlsModel "github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"net/url"
)

// GetKeyWithURL method is used to get the image flavor-key from the workload service
func GetKeyWithURL(keyUrl string, hardwareUUID string) (wlsModel.ReturnKey, error) {
	log.Trace("clients/workload_service_client:GetKeyWithURL() Entering")
	defer log.Trace("clients/workload_service_client:GetKeyWithURL() Leaving")
	var retKey wlsModel.ReturnKey

	requestUrl, err := url.ParseRequestURI(viper.GetString(constants.WlsApiUrlViperKey))
	if err != nil {
		return retKey, errors.New("client/workload_service_client:GetKeyWithURL() error retrieving WLS API URL")
	}
	keysPathUrl, err := url.Parse(constants.WlsKeysEndPoint)
	if err != nil {
		return retKey, errors.New("client/workload_service_client:GetKeyWithURL() error retrieving WLS API URL")
	}
	requestUrl = requestUrl.ResolveReference(keysPathUrl)

	wlsClientFactory, err := wlsclient.NewWLSClientFactory(viper.GetString(constants.WlsApiUrlViperKey), viper.GetString(constants.AasBaseUrlViperKey),
		viper.GetString(constants.WlaUsernameViperKey), viper.GetString(constants.WlaPasswordViperKey), constants.TrustedCaCertsDir)
	if err != nil {
		return retKey, errors.Wrap(err, "Error while instantiating WLSClientFactory")

	}

	keysClient, err := wlsClientFactory.KeysClient()
	if err != nil {
		return retKey, errors.Wrap(err, "Error while instantiating KeysClient")
	}

	retKey, err = keysClient.GetKeyWithURL(keyUrl, hardwareUUID)
	if err != nil {
		return retKey, errors.Wrap(err, "Error while getting key")
	}
	log.Debug("client/workload_service_client:GetKeyWithURL() Successfully retrieved Key")
	return retKey, nil
}
