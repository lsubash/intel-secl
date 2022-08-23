/*
* Copyright (C) 2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"encoding/json"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/middleware"

	"io/ioutil"
	"net/http"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"
)

// Reprovision existing ima policy for new set of input files.
func ReprovisionImaPolicy(requestHandler common.RequestHandler) middleware.EndpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("controllers/reprovision_ima:ReprovisionImaPolicy() Entering")
		defer log.Trace("controllers/reprovision_ima:ReprovisionImaPolicy() Leaving")

		log.Debugf("controllers/reprovision_ima:ReprovisionImaPolicy() Request: %s", httpRequest.URL.Path)

		var reprovisionImaRequest taModel.ReprovisionImaRequest
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/json" {
			log.Errorf("controllers/reprovision_ima:ReprovisionImaPolicy() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		// receive list of files from hvs in the request body
		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.WithError(err).Errorf("controllers/reprovision_ima:ReprovisionImaPolicy() %s - Error reading request body for request: %s", message.AppRuntimeErr, httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error parsing request", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&reprovisionImaRequest)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/reprovision_ima:ReprovisionImaPolicy() %s - Error marshaling json data: %s for request: %s", message.InvalidInputBadParam, string(data), httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error processing request", StatusCode: http.StatusBadRequest}
		}

		err = requestHandler.ProvisionImaFiles(constants.ReprovisonFileList, &reprovisionImaRequest)
		if err != nil {
			log.WithError(err).Errorf("controllers/reprovision_ima:ReprovisionImaPolicy() %s - Error while reprovisioning ima policy", message.AppRuntimeErr)
			return err
		}

		httpWriter.WriteHeader(http.StatusOK)
		return nil
	}
}
