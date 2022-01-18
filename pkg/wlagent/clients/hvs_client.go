/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package clients

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/hvsclient"
	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	wlaModel "github.com/intel-secl/intel-secl/v5/pkg/model/wlagent"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var log = cLog.GetDefaultLogger()
var secLog = cLog.GetSecurityLogger()

// Error is an error struct that contains error information thrown by the actual HVS
type Error struct {
	StatusCode int
	Message    string
}

func (e Error) Error() string {
	return fmt.Sprintf("hvs-client: failed (HTTP Status Code: %d)\nMessage: %s", e.StatusCode, e.Message)
}

// CertifyHostSigningKey sends a POST to /certify-host-signing-key to register signing key with HVS
func CertifyHostSigningKey(hvsApiUrl string, key *wlaModel.RegisterKeyInfo) (*wlaModel.SigningKeyCert, error) {
	log.Trace("clients/hvs_client:CertifyHostSigningKey() Entering")
	defer log.Trace("clients/hvs_client:CertifyHostSigningKey() Leaving")
	var keyCert wlaModel.SigningKeyCert

	rsp, err := certifyHostKey(hvsApiUrl, key, constants.SigningKeyType)
	if err != nil {
		return nil, errors.Wrap(err, "clients/hvs_client:CertifyHostSigningKey()  error registering signing key with HVS")
	}
	err = json.Unmarshal(rsp, &keyCert)
	if err != nil {
		log.Debugf("Could not unmarshal json from /rpc/certify-host-signing-key: %s", string(rsp))
		return nil, errors.Wrap(err, "clients/hvs_client:CertifyHostSigningKey() error decoding signing key certificate")
	}
	return &keyCert, nil
}

// CertifyHostBindingKey sends a POST to /certify-host-binding-key to register binding key with HVS
func CertifyHostBindingKey(hvsApiUrl string, key *wlaModel.RegisterKeyInfo) (*wlaModel.BindingKeyCert, error) {
	log.Trace("clients/hvs_client:CertifyHostBindingKey Entering")
	defer log.Trace("clients/hvs_client:CertifyHostBindingKey Leaving")
	var keyCert wlaModel.BindingKeyCert
	rsp, err := certifyHostKey(hvsApiUrl, key, constants.BindingKeyType)
	if err != nil {
		return nil, errors.Wrap(err, "clients/hvs_client:CertifyHostBindingKey() error registering binding key with HVS")
	}
	err = json.Unmarshal(rsp, &keyCert)
	if err != nil {
		log.Debugf("Could not unmarshal json from /rpc/certify-host-binding-key: %s", string(rsp))
		return nil, errors.Wrap(err, "clients/hvs_client:CertifyHostBindingKey() error decoding binding key certificate.")
	}
	return &keyCert, nil
}

func certifyHostKey(hvsApiUrl string, keyInfo *wlaModel.RegisterKeyInfo, keyUsage string) ([]byte, error) {
	log.Trace("clients/hvs_client:certifyHostKey Entering")
	defer log.Trace("clients/hvs_client:certifyHostKey Leaving")

	jwtToken := strings.TrimSpace(viper.GetString("bearer-token"))
	if jwtToken == "" {
		fmt.Fprintf(os.Stderr, "%s is not defined in environment", constants.BearerTokenEnv)
		return nil, errors.Errorf("%s is not defined in environment", constants.BearerTokenEnv)
	}

	vsClientFactory, err := hvsclient.NewVSClientFactory(hvsApiUrl, jwtToken, constants.TrustedCaCertsDir)
	if err != nil {
		return nil, errors.Wrap(err, "Error while instantiating VSClientFactory")
	}

	certifyHostKeysClient, err := vsClientFactory.CertifyHostKeysClient()
	if err != nil {
		return nil, errors.Wrap(err, "Error while instantiating CertifyHostKeysClient")
	}

	var responseData []byte
	if keyUsage == "signing" {
		responseData, err = certifyHostKeysClient.CertifyHostSigningKey(keyInfo)
	} else {
		responseData, err = certifyHostKeysClient.CertifyHostBindingKey(keyInfo)
	}
	if err != nil {
		return nil, errors.Wrap(err, "Error from response")
	}

	return responseData, nil
}
