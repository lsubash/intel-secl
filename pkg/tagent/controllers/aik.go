/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/middleware"
	"net/http"

	"github.com/intel-secl/intel-secl/v5/pkg/tagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
)

var (
	log    = commLog.GetDefaultLogger()
	secLog = commLog.GetSecurityLogger()
)

func GetAik(requestHandler common.RequestHandler) middleware.EndpointHandler {

	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/aik:GetAik) Entering")
		defer log.Trace("controllers/aik:GetAik) Leaving")

		log.Debugf("controllers/aik:GetAik) Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type to /aik, so only allow the empty string...
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("controllers/aik:GetAik) %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		aikDer, err := requestHandler.GetAikDerBytes()
		if err != nil {
			log.WithError(err).Errorf("controllers/aik:GetAik) %s - There was an error reading %s", message.AppRuntimeErr, constants.AikCert)
			return &common.EndpointError{Message: "Unable to fetch AIK certificate", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(aikDer).WriteTo(httpWriter)
		return nil
	}
}
