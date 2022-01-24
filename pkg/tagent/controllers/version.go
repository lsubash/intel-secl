/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/middleware"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/version"
	"net/http"
)

// getVersion handles GET /version
func GetVersion() middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/version:GetVersion() Entering")
		defer log.Trace("controllers/version:GetVersion() Leaving")

		httpWriter.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		log.Debugf("controllers/version:GetVersion() Trust Agent Version:\n %s", version.GetVersion())
		httpWriter.Header().Set("Content-Type", "text/plain")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer([]byte(version.GetVersion())).WriteTo(httpWriter)
		return nil
	}
}
