/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"net/http"
	"strings"
)

func (icon *ImageController) GetAssociatedFlavorv1(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("controllers/images_controller:GetAssociatedFlavorv1() Entering")
	defer defaultLog.Trace("controllers/images_controller:GetAssociatedFlavorv1() Leaving")

	imageUUID, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavorv1() %s : Invalid UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - Invalid image UUID format"}
	}

	flavorUUID, err := uuid.Parse(mux.Vars(r)["flavorID"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavorv1() %s : Invalid flavor UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - Invalid image UUID format"}
	}

	flavor, err := icon.IStore.RetrieveFlavorV1(imageUUID, flavorUUID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavorv1() %s : Failed to retrieve associated flavor for image", message.AppRuntimeErr)
			secLog.Debug(err.Error())
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - No flavor associated with given image UUID"}
		} else {
			secLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavorv1() %s : Failed to retrieve associated flavor for image", message.AppRuntimeErr)
			secLog.Tracef("%+v", err)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - backend error"}
		}
	}

	defaultLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).Info("controllers/images_controller:GetAssociatedFlavorv1() Successfully retrieved associated Flavor")
	secLog.Infof("%s: Flavor associated with image Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavor, http.StatusOK, nil
}

func (icon *ImageController) GetAllAssociatedFlavorsv1(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/images_controller:GetAllAssociatedFlavorsv1() Entering")
	defer defaultLog.Trace("controllers/images_controller:GetAllAssociatedFlavorsv1() Leaving")

	uuid, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:GetAllAssociatedFlavorsv1() %s : Invalid UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve associated flavors - Invalid image UUID format"}
	}

	flavors, err := icon.IStore.RetrieveFlavorsV1(uuid)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithField("uuid", uuid).WithError(err).Errorf("controllers/images_controller:GetAllAssociatedFlavorsv1() %s : Failed to retrieve associated flavors for image", message.AppRuntimeErr)
			defaultLog.Tracef("%+v", err)
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Image entry not found"}
		} else {
			defaultLog.WithField("uuid", uuid).WithError(err).Errorf("controllers/images_controller:GetAllAssociatedFlavorsv1() %s : Failed to retrieve associated flavors for image", message.AppRuntimeErr)
			defaultLog.Tracef("%+v", err)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve associated flavors - backend error"}
		}
	}

	defaultLog.WithField("uuid", uuid).Info("controllers/images_controller:GetAllAssociatedFlavorsv1() Successfully retrieved associated flavors for image")
	secLog.Infof("%s: Flavor associated with image Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavors, http.StatusOK, nil
}
