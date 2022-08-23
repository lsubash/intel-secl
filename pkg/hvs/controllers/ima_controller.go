/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/model/hvs"
	"github.com/pkg/errors"
)

type ImaController struct {
	HController HostController
}

func NewImaController(hs domain.HostStore, hcConfig domain.HostControllerConfig) *ImaController {
	hc := HostController{
		HStore:   hs,
		HCConfig: hcConfig,
	}
	return &ImaController{
		HController: hc,
	}
}

func (icon *ImaController) UpdateImaMeasurements(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ima_controller:UpdateImaMeasurements() Entering")
	defer defaultLog.Trace("controllers/ima_controller:UpdateImaMeasurements() Leaving")

	flavorUpdateReq, err := icon.getImaUpdateReq(r)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid Content-Type") {
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
		}
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	if flavorUpdateReq.ConnectionString != "" {
		defaultLog.Info("controllers/ima_controller:UpdateImaMeasurements() Host connection string given, trying to send ima folder details")
		connectionString, _, err := GenerateConnectionString(flavorUpdateReq.ConnectionString,
			icon.HController.HCConfig.Username,
			icon.HController.HCConfig.Password,
			icon.HController.HCStore)

		if err != nil {
			defaultLog.Error("controllers/ima_controller:UpdateImaMeasurements() Could not generate formatted connection string")
			return nil, http.StatusInternalServerError, errors.Wrap(err, "Error while generating a formatted connection string")
		}

		defaultLog.Info("controllers/ima_controller:UpdateImaMeasurements() After generating connectionstring ", connectionString)

		hostConnector, err := icon.HController.HCConfig.HostConnectorProvider.NewHostConnector(connectionString)
		if err != nil {
			return nil, http.StatusInternalServerError, errors.Wrap(err, "Could not instantiate host connector")
		}

		if err := validation.ValidateStrings(flavorUpdateReq.Files); err != nil {
			return nil, http.StatusInternalServerError, errors.Wrap(err, "Valid file names must be specified")
		}

		err = hostConnector.SendImaFilelist(flavorUpdateReq.Files)
		if err != nil {
			return nil, http.StatusInternalServerError, errors.Wrap(err, "Could not send Ima file list to TA")
		}

	} else {
		return nil, http.StatusBadRequest, errors.Wrap(err, "Connection string is empty, could not send Ima file list to TA")
	}

	secLog.Info("controllers/ima_controller:UpdateImaMeasurements() Ima file list folders sent to TA successfully")
	return "New IMA measurements appended successfully. Restart Trustagent. User need to delete old IMA flavor and create new IMA flavor if flavor update is pending", http.StatusOK, nil
}

// getImaUpdateReq This method is used to get the body content of Ima Flavor Update Request
func (icon *ImaController) getImaUpdateReq(r *http.Request) (hvs.UpdateImaMeasurementsReq, error) {
	defaultLog.Trace("controllers/ima_controller:getImaUpdateReq() Entering")
	defer defaultLog.Trace("controllers/ima_controller:getImaUpdateReq() Leaving")

	var UpdateImaMeasurementsReq hvs.UpdateImaMeasurementsReq
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		defaultLog.Error("controllers/ima_controller:getImaUpdateReq() Invalid Content-Type")
		return UpdateImaMeasurementsReq, &commErr.UnsupportedMediaError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		defaultLog.Error("controllers/ima_controller:getImaUpdateReq() The request body is not provided")
		return UpdateImaMeasurementsReq, &commErr.BadRequestError{Message: "The request body is not provided"}
	}

	//Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&UpdateImaMeasurementsReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/ima_controller:getImaUpdateReq() Unable to decode request body")
		return UpdateImaMeasurementsReq, &commErr.BadRequestError{Message: "Unable to decode request body"}
	}

	return UpdateImaMeasurementsReq, nil
}
