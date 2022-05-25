/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"io/ioutil"
	"net/http"
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"
)

func (handler *requestHandlerImpl) GetBindingCertificateDerBytes(bindingKeyCertificatePath string) ([]byte, error) {
	if _, err := os.Stat(bindingKeyCertificatePath); os.IsNotExist(err) {
		log.WithError(err).Errorf("common/binding_key_certificate:getBindingKeyCertificate() %s - %s does not exist", message.AppRuntimeErr, constants.BindingKeyCertificatePath)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	bindingKeyBytes, err := ioutil.ReadFile(bindingKeyCertificatePath)
	if err != nil {
		log.WithError(err).Errorf("common/binding_key_certificate:getBindingKeyCertificate() %s - Error reading %s", message.AppRuntimeErr, constants.BindingKeyCertificatePath)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

	}

	return bindingKeyBytes, nil
}
