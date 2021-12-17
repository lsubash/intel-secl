/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ReportController struct {
	ReportStore domain.ReportStore
}

func NewReportController(rs domain.ReportStore) *ReportController {
	return &ReportController{rs}
}

func (rc ReportController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Create() Entering")
	defer defaultLog.Trace("controllers/report_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/report_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var vtr model.Report
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vtr); err != nil {
		defaultLog.WithError(err).Errorf("controllers/report_controller:Create() %s : Report creation failed", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}
	if err := json.Unmarshal(vtr.Data, &vtr.InstanceTrustReport); err != nil {
		defaultLog.WithError(err).Errorf("controllers/report_controller:Create() %s : Report creation failed", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Report creation failed - Unable to marshall Instance Trust Report"}
	}

	// Performance Related:
	// currently, we don't decipher the creation error to see if Creation failed because a collision happened between a primary or unique key.
	// It would be nice to know why the record creation fails, and return the proper http status code.
	// It could be done several ways:
	// - Type assert the error back to PSQL (should be done in the repository layer), and bubble up that information somehow
	// - Manually run a query to see if anything exists with uuid or label (should be done in the repository layer, so we can execute it in a transaction)
	//    - Currently doing this ^
	createdReport, err := rc.ReportStore.Create(&vtr)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/report_controller:Create() Failed to create Report")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Report creation failed"}
	}
	secLog.Infof("%s: Report created by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return createdReport, http.StatusCreated, nil
}

func (rc ReportController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Search() Entering")
	defer defaultLog.Trace("controllers/report_controller:Search() Leaving")

	// get the ReportFilterCriteria
	reportFilterCriteria, err := getReportFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Warnf("controllers/report_controller:Search() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Input given in request"}
	}

	reportCollection, err := rc.ReportStore.Search(reportFilterCriteria)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/report_controller:Search() Report search operation failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Report search operation failed")
	}
	secLog.Infof("%s: Reports searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return reportCollection, http.StatusOK, nil
}

func (rc ReportController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/report_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	vmReport, err := rc.ReportStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/report_controller:Retrieve() Report with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Report with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/report_controller:Retrieve() failed to retrieve Report")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Report"}
		}
	}
	secLog.WithField("report", vmReport).Infof("%s: Report retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return vmReport, http.StatusOK, nil
}

func (rc *ReportController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/report_controller:Delete() Leaving")

	reportId := uuid.MustParse(mux.Vars(r)["id"])
	_, err := rc.ReportStore.Retrieve(reportId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", reportId).Info(
				"controllers/report_controller:Delete()  Report with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Report with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", reportId).Info(
				"controllers/report_controller:Delete() Failed to delete Report")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Report"}
		}
	}

	if err := rc.ReportStore.Delete(reportId); err != nil {
		defaultLog.WithError(err).WithField("id", reportId).Info(
			"controllers/report_controller:Delete() failed to delete Report")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Report"}
	}
	secLog.Infof("%s: Report deleted by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

// getReportFilterCriteria checks for set filter params in the Search request and returns a valid ReportFilterCriteria
func getReportFilterCriteria(params url.Values) (*model.ReportFilter, error) {
	defaultLog.Trace("controllers/report_controller:getReportFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/report_controller:getReportFilterCriteria() Leaving")

	rfc := model.ReportFilter{}

	// Report ID
	if strings.TrimSpace(params.Get("id")) != "" {
		id, err := uuid.Parse(strings.TrimSpace(params.Get("id")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Report Identifier specified")
		}
		rfc.ReportID = id
	}

	//Instance ID
	if strings.TrimSpace(params.Get("instanceId")) != "" {
		instanceId, err := uuid.Parse(strings.TrimSpace(params.Get("instanceId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the instance specified")
		}
		rfc.InstanceID = instanceId
	}

	// Host Hardware UUID
	if params.Get("hostHardwareId") != "" {
		hostHardwareId, err := uuid.Parse(strings.TrimSpace(params.Get("hostHardwareId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host Hardware Identifier specified")
		}
		rfc.HardwareUUID = hostHardwareId
	}

	// fromDate
	fromDate := strings.TrimSpace(params.Get("fromDate"))
	if fromDate != "" {
		pTime, err := parseDateQueryParam(fromDate)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid fromDate specified")
		}
		rfc.FromDate = pTime
	}

	// toDate
	toDate := strings.TrimSpace(params.Get("toDate"))
	if toDate != "" {
		pTime, err := parseDateQueryParam(toDate)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid toDate specified")
		}
		rfc.ToDate = pTime
	}

	latestPerVM := strings.TrimSpace(strings.ToLower(params.Get("latestPerVM")))
	if latestPerVM != "" {
		lpv, err := strconv.ParseBool(latestPerVM)
		if err != nil {
			return nil, errors.Wrap(err, "latestPerHost must be true or false")
		}
		rfc.LatestPerVM = lpv
	}

	// numberOfDays - defaults to 0
	numberOfDays := strings.TrimSpace(params.Get("numberOfDays"))
	if numberOfDays != "" {
		numDays, err := strconv.Atoi(numberOfDays)
		if err != nil || numDays < 0 {
			return nil, errors.New("NumberOfDays must be an integer >= 0")
		}
		rfc.NumberOfDays = numDays
	}

	return &rfc, nil
}

func parseDateQueryParam(dt string) (time.Time, error) {
	defaultLog.Trace("utils/controller:ParseDateQueryParam() Entering")
	defer defaultLog.Trace("utils/controller:ParseDateQueryParam() Leaving")
	pTime, err := time.Parse(constants.ParamDateFormat, dt)
	if err != nil {
		pTime, err = time.Parse(constants.ParamDateTimeFormat, dt)
		if err != nil {
			pTime, err = time.Parse(time.RFC3339Nano, dt)
			if err != nil {
				return time.Time{}, errors.Wrap(err, "One of Valid date formats (YYYY-MM-DD)|(YYYY-MM-DD hh:mm:ss)|(YYYY-MM-DDThh:mm:ss.000Z)|(YYYY-MM-DDThh:mm:ss.000000Z) must be specified")
			}
		}
	}
	return pTime, nil
}
