/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain"
	dm "github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strings"
)

type FlavorController struct {
	FStore domain.FlavorStore
}

const duplicateKeyError = "duplicate key"

var flavorSearchParams = map[string]bool{"id": true, "label": true}

func NewFlavorController(fs domain.FlavorStore) *FlavorController {
	return &FlavorController{
		FStore: fs,
	}
}

func (fcon *FlavorController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Create() Leaving")

	f, err := validateFlavor(r)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid Content-Type") {
			return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
		}
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	if f.ImageFlavor.Meta.Description.FlavorPart == "" || (f.ImageFlavor.Meta.Description.FlavorPart != "CONTAINER_IMAGE" && f.ImageFlavor.Meta.Description.FlavorPart != "IMAGE") {
		defaultLog.Errorf("controllers/flavor_controller/flavors:create() : Failed to create flavor: flavor_part should be either of CONTAINER_IMAGE or IMAGE")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "flavor_part should be either of CONTAINER_IMAGE or IMAGE"}
	}

	if f.Signature == "" {
		defaultLog.Errorf("controllers/flavor_controller/flavors:create() : Failed to create flavor: Flavor signature is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor signature is not provided"}
	}

	flavorDoesNotExist := false
	_, err = fcon.FStore.Retrieve(f.ImageFlavor.Meta.ID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			flavorDoesNotExist = true
		} else {
			secLog.WithError(err).WithField("id", f.ImageFlavor.Meta.ID).Info(
				"controllers/flavor_controller:Create() failed to retrieve Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor with the given ID"}
		}
	}

	if !flavorDoesNotExist {
		defaultLog.WithError(err).Error("controllers/flavor_controller:Create() Flavor with given ID already exist")
		return nil, http.StatusConflict, &commErr.ResourceError{Message: "Flavor with given ID already exists"}
	}

	createdFlavor, err := fcon.FStore.Create(&f)
	if err != nil {
		if strings.Contains(err.Error(), duplicateKeyError) {
			return nil, http.StatusConflict, &commErr.ResourceError{Message: "Flavor with given label already exists"}
		} else {
			defaultLog.WithError(err).Error("controllers/flavor_controller:Create() Create Flavor failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
		}
	}
	defaultLog.Info("Flavors created successfully")
	secLog.Infof("%s: Flavor created by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return createdFlavor, http.StatusCreated, nil
}

func ValidateQueryParams(params url.Values, validQueries map[string]bool) error {
	defaultLog.Trace("controllers/flavor_controller:ValidateQueryParams() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:ValidateQueryParams() Leaving")

	for param := range params {
		if _, hasQuery := validQueries[param]; !hasQuery {
			return errors.New("Invalid query parameter provided. Refer to product guide for details.")
		}
	}
	return nil
}

func (fcon *FlavorController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query flavors")
	id := r.URL.Query().Get("id")
	label := r.URL.Query().Get("label")

	if err := ValidateQueryParams(r.URL.Query(), flavorSearchParams); err != nil {
		secLog.Errorf("controllers/flavor_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid filter criteria provided, allowed filter criterias are id and label"}
	}

	filterCriteria, err := validateFlavorFilterCriteria(id, label)
	if err != nil {
		secLog.Errorf("controllers/flavor_controller:Search()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	signedFlavors, err := fcon.FStore.Search(filterCriteria)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavor_controller:Search() Flavor get all failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search Flavors"}
	}

	secLog.Infof("%s: Return flavor query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return dm.SignedFlavorCollection{Flavors: signedFlavors}, http.StatusOK, nil
}

func (fcon *FlavorController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Delete() Leaving")

	flavorId := uuid.MustParse(mux.Vars(r)["id"])
	_, err := fcon.FStore.Retrieve(flavorId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", flavorId).Info(
				"controllers/flavor_controller:Delete()  Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", flavorId).Info(
				"controllers/flavor_controller:Delete() Failed to delete Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
		}
	}

	if err := fcon.FStore.Delete(flavorId); err != nil {
		defaultLog.WithError(err).WithField("id", flavorId).Info(
			"controllers/flavor_controller:Delete() failed to delete Flavor")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
	}
	secLog.Infof("%s: Flavor Deleted by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (fcon *FlavorController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	signedFlavor, err := fcon.FStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() failed to retrieve Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor with the given ID"}
		}
	}
	secLog.Infof("%s: Flavor Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return signedFlavor, http.StatusOK, nil
}

func validateFlavorFilterCriteria(id, label string) (*dm.FlavorFilter, error) {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Leaving")

	filterCriteria := dm.FlavorFilter{}
	var err error
	var parsedId uuid.UUID

	if id != "" {
		parsedId, err = uuid.Parse(id)
		if err != nil {
			return nil, errors.New("Invalid UUID format of the flavor identifier")
		}
	}

	filterCriteria.FlavorID = parsedId

	if label != "" {
		if err = validation.ValidateStrings([]string{label}); err != nil {
			return nil, errors.Wrap(err, "Valid contents for filter label must be specified")
		}
	}
	filterCriteria.Label = label
	return &filterCriteria, nil
}

func validateFlavor(r *http.Request) (wls.SignedImageFlavor, error) {
	defaultLog.Trace("controllers/flavor_controller:validateFlavor() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavor() Leaving")

	var signedFlavor wls.SignedImageFlavor
	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		secLog.Error("controllers/flavor_controller:validateFlavor() Invalid Content-Type")
		return signedFlavor, errors.New("Invalid Content-Type")
	}

	defaultLog.Infof("controllers/flavor_controller:validateFlavor() Request to create host_unique flavors received")
	if r.ContentLength == 0 {
		secLog.Error("controllers/flavor_controller:validateFlavor() The request body is not provided")
		return signedFlavor, errors.New("The request body is not provided")
	}

	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&signedFlavor)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/flavor_controller:validateFlavor() %s :  Failed to decode request body as Flavor", commLogMsg.InvalidInputBadEncoding)
		return signedFlavor, errors.New("Unable to decode JSON request body")
	}

	return signedFlavor, nil
}
