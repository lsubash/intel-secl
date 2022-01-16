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
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
	"net/http"
	"strings"
)

type ImageController struct {
	IStore    domain.ImageStore
	FStore    domain.FlavorStore
	conf      *config.Configuration
	CertStore *crypt.CertificatesStore
}

func NewImageController(imgs domain.ImageStore, fs domain.FlavorStore, conf *config.Configuration, certStore *crypt.CertificatesStore) *ImageController {
	return &ImageController{
		IStore:    imgs,
		FStore:    fs,
		conf:      conf,
		CertStore: certStore,
	}
}

var imageSearchParams = map[string]bool{"flavor_id": true, "image_id": true}
var allowedFlavorPart = [2]string{"CONTAINER_IMAGE", "IMAGE"}

func (icon *ImageController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/image_controller:Create() Entering")
	defer defaultLog.Trace("controllers/image_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/image_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var formBody model.Image
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&formBody); err != nil {
		defaultLog.WithError(err).Errorf("controllers/image_controller:Create() %s : Failed to encode request body as Image", message.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	// validate input format
	if err := validation.ValidateUUIDv4(formBody.ID.String()); err != nil {
		secLog.WithError(err).Errorf("controllers/image_controller:Create() %s : Invalid image UUID format", message.InvalidInputProtocolViolation)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid image UUID format"}
	}

	for i := range formBody.FlavorIDs {
		if err := validation.ValidateUUIDv4(formBody.FlavorIDs[i].String()); err != nil {
			secLog.Errorf("resource/images:create() %s : Invalid flavor UUID format", message.InvalidInputProtocolViolation)
			secLog.Tracef("%+v", err)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid flavor UUID format"}
		}
	}

	if err := icon.IStore.Create(&formBody); err != nil {
		switch err {
		case postgres.ErrImageAssociationFlavorDoesNotExist:
			defaultLog.WithField("image", formBody).WithError(err).Errorf("controllers/image_controller:Create() %s : One or more flavor IDs does not exist", message.AppRuntimeErr)
			defaultLog.Tracef("%+v", err)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "One or more flavor IDs does not exist"}
		default:
			defaultLog.WithField("image", formBody).Errorf("controllers/image_controller:Create() %s : Unexpected error when creating image", message.AppRuntimeErr)
			defaultLog.Tracef("%+v", err)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unexpected error when creating image, check input format"}
		}
	}

	defaultLog.WithField("image", formBody).Debug("controllers/image_controller:Create() Successfully created Image")
	secLog.Infof("%s: Image created by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return formBody, http.StatusCreated, nil
}

func (icon *ImageController) DeleteImageFlavorAssociation(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/image_controller:DeleteImageFlavorAssociation() Entering")
	defer defaultLog.Trace("controllers/image_controller:DeleteImageFlavorAssociation() Leaving")

	imageUUID, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/image_controller:DeleteImageFlavorAssociation() %s : Invalid image UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to delete image - Invalid image UUID format"}
	}

	flavorUUID, err := uuid.Parse(mux.Vars(r)["flavorID"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/image_controller:DeleteImageFlavorAssociation() %s : Invalid flavor UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to delete image - Invalid flavor UUID format"}
	}

	err = icon.IStore.DeleteImageFlavorAssociation(imageUUID, flavorUUID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", imageUUID).Error(
				"controllers/image_controller:DeleteImageFlavorAssociation()  Image with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Image Flavor association with given IDs does not exist"}
		} else {
			defaultLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).WithError(err).Errorf("controllers/image_controller:DeleteImageFlavorAssociation() %s : Failed to remove Flavor association for Image", message.AppRuntimeErr)
			defaultLog.Tracef("%+v", err)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete image/flavor association - Backend error"}
		}
	}

	defaultLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).Debug("controllers/image_controller:DeleteImageFlavorAssociation() Successfully removed Flavor association for Image")
	secLog.Infof("%s: Delete Image Flavor Association by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (icon *ImageController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/image_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/image_controller:Delete() Leaving")

	imageId, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/image_controller:Delete() %s : Invalid image UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to delete image - Invalid image UUID format"}
	}

	if err := icon.IStore.Delete(imageId); err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", imageId).Error(
				"controllers/image_controller:Delete()  Image with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Image with given ID does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", imageId).Info(
				"controllers/image_controller:Delete() failed to delete Image")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Image"}
		}
	}
	secLog.Infof("%s: Image deleted by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (icon *ImageController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/image_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/image_controller:Retrieve() Leaving")

	imageId, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/image_controller:Retrieve()  %s : Invalid image UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve image - Invalid image UUID format"}
	}

	image, err := icon.IStore.Retrieve(imageId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", imageId).Errorf(
				"controllers/image_controller:Retrieve() Image with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Image with given ID does not exist"}
		} else {
			defaultLog.WithField("image id", imageId).Error("Failed to retrieve image - Backend error for image")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve image - Backend error"}
		}
	}

	defaultLog.WithField("id", imageId).Info("controllers/image_controller:Retrieve() Successfully retrieved Image by UUID")
	secLog.Infof("%s: Image Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return image, http.StatusOK, nil
}

func (icon *ImageController) RetrieveFlavorForFlavorPart(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/image_controller:RetrieveFlavorForFlavorPart() Entering")
	defer defaultLog.Trace("controllers/images_controller:RetrieveFlavorForFlavorPart() Leaving")

	imageId, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/image_controller:RetrieveFlavorForFlavorPart() %s : Invalid image UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve flavor - Invalid image UUID format"}
	}

	flavorPart := mux.Vars(r)["flavor_part"]
	if flavorPart == "" {
		defaultLog.Errorf("controllers/image_controller:RetrieveFlavorForFlavorPart() %s : Missing required parameter flavor_part %s", message.InvalidInputBadParam, flavorPart)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve flavor - Query parameter 'flavor_part' cannot be nil"}
	}
	// validate flavor part
	fpArr := []string{flavorPart}
	if validateInputErr := validation.ValidateStrings(fpArr); validateInputErr != nil {
		secLog.WithError(validateInputErr).Errorf("controllers/image_controller:RetrieveFlavorForFlavorPart() %s : Invalid flavor part string format", message.InvalidInputProtocolViolation)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve flavor - Invalid flavor part string format"}
	}

	if flavorPart == allowedFlavorPart[0] || flavorPart == allowedFlavorPart[1] {
		flavor, err := icon.IStore.RetrieveAssociatedFlavorByFlavorPart(imageId, flavorPart)

		if err != nil {
			if strings.Contains(err.Error(), commErr.RowsNotFound) {
				defaultLog.WithField("imageUUID", imageId).WithField("flavorPart", flavorPart).WithError(err).Errorf("controllers/image_controller:RetrieveFlavorForFlavorPart() %s : Failed to retrieve Flavor for Image", message.AppRuntimeErr)
				defaultLog.Tracef("%+v", err)
				return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Failed to retrieve flavor - No flavor found for given image ID"}
			} else {
				defaultLog.WithField("imageUUID", imageId).WithField("flavorPart", flavorPart).WithError(err).Errorf("controllers/image_controller:RetrieveFlavorForFlavorPart() %s : Internal server error", message.AppRuntimeErr)
				return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve image - Backend error"}
			}
		}
		secLog.Infof("%s: Flavor Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return &flavor, http.StatusOK, nil
	} else {
		defaultLog.Error("controllers/image_controller:RetrieveFlavorForFlavorPart() Invalid input to flavor_part parameter")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve flavor - Invalid input to flavor_part parameter"}
	}
}

func (icon *ImageController) RetrieveFlavorAndKey(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/images_controller:RetrieveFlavorAndKey() Entering")
	defer defaultLog.Trace("controllers/images_controller:RetrieveFlavorAndKey() Leaving")

	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.Errorf("controllers/images_controller:RetrieveFlavorAndKey() %s : Invalid UUID format - %s", message.InvalidInputProtocolViolation, id)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve flavor - Invalid image UUID format"}
	}

	hwid := mux.Vars(r)["hardware_uuid"]
	// validate hardware UUID
	if err := validation.ValidateHardwareUUID(hwid); err != nil {
		defaultLog.Errorf("controllers/images_controller:RetrieveFlavorAndKey() %s : Invalid hardware UUID format - %s", message.InvalidInputProtocolViolation, hwid)
		defaultLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve Flavor/Key - Invalid hardware uuid"}
	}

	defaultLog.WithField("imageUUID", id).WithField("hardwareUUID", hwid).Trace("controllers/images_controller:RetrieveFlavorAndKey() Retrieving Flavor and Key for Image")
	flavor, err := icon.IStore.RetrieveImageFlavor(id)
	if err != nil {
		defaultLog.WithField("imageUUID", id).WithField("hardwareUUID", hwid).WithError(err).Errorf("controllers/images_controller:RetrieveFlavorAndKey() %s : Failed to retrieve Flavor and Key for Image", message.AppRuntimeErr)
		return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Failed to retrieve Flavor and Key for Image"}
	}

	keyUrl := flavor.ImageFlavor.Encryption.KeyURL
	// Check if flavor keyUrl is not empty
	if flavor.ImageFlavor.EncryptionRequired && len(flavor.ImageFlavor.Encryption.KeyURL) > 0 {
		key, err := transfer_key(true, hwid, keyUrl, id.String(), icon.conf, icon.CertStore)
		if err != nil {
			defaultLog.WithField("imageUUID", id).WithField("hardwareUUID", hwid).WithError(err).Error("controllers/images_controller:RetrieveFlavorAndKey() Error while retrieving key")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: " Error while retrieving key"}
		}

		// got key data
		flavorKey := wls.FlavorKey{
			Flavor:    flavor.ImageFlavor,
			Signature: flavor.Signature,
			Key:       key,
		}

		defaultLog.WithField("imageUUID", id).WithField("hardwareUUID", hwid).Info("controllers/images_controller:RetrieveFlavorAndKey() Successfully retrieved FlavorKey")
		secLog.Infof("%s: Flavor Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return flavorKey, http.StatusOK, nil
	} else {
		defaultLog.WithField("imageUUID", id).Errorf("controllers/images_controller:RetrieveFlavorAndKey() Key URL is empty")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Key URL is empty"}
	}
	// just return the flavor
	flavorKey := wls.FlavorKey{Flavor: flavor.ImageFlavor, Signature: flavor.Signature}

	defaultLog.WithField("imageUUID", id).WithField("hardwareUUID", hwid).Info("controllers/images_controller:RetrieveFlavorAndKey() Successfully retrieved Flavor and Key")
	secLog.Infof("%s: Flavor Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavorKey, http.StatusOK, nil
}

func (icon *ImageController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/images_controller:Search() Entering")
	defer defaultLog.Trace("controllers/images_controller:Search() Leaving")

	if err := ValidateQueryParams(r.URL.Query(), imageSearchParams); err != nil {
		secLog.Errorf("controllers/images_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid filter criteria provided, allowed filter criterias are flavor_id, image_id"}
	}

	locator := model.ImageFilter{}

	flavorID, ok := r.URL.Query()["flavor_id"]
	if ok && len(flavorID[0]) >= 1 {
		flavorUUID, err := uuid.Parse(flavorID[0])
		if err != nil {
			secLog.WithError(err).Errorf("controllers/images_controller:Search() %s : Invalid flavor UUID format", message.InvalidInputProtocolViolation)
			secLog.Tracef("%+v", err)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve image - Invalid image UUID format"}
		}
		locator.FlavorID = flavorUUID
	}

	imageID, ok := r.URL.Query()["image_id"]
	if ok && len(imageID[0]) >= 1 {
		imageUUID, err := uuid.Parse(imageID[0])
		if err != nil {
			secLog.WithError(err).Errorf("controllers/images_controller:Search() %s : Invalid image UUID format", message.InvalidInputProtocolViolation)
			secLog.Tracef("%+v", err)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve image - Invalid image UUID format"}
		}
		locator.ImageID = imageUUID
	}

	if locator.FlavorID.String() == "" && locator.ImageID.String() == "" {
		defaultLog.Errorf("controllers/images_controller:Search() %s : Invalid filter criteria. Allowed filter critierias are image_id, flavor_id \n", message.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve image - Invalid filter criteria. Allowed filter criteria are image_id, flavor_id"}
	}

	images, err := icon.IStore.Search(locator)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/images_controller:Search() %s : Failed to retrieve Images by filter criteria", message.AppRuntimeErr)
		defaultLog.Tracef("%+v", err)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve image - Failed to retrieve Images by filter criteria"}
	}

	defaultLog.Info("controllers/images_controller:Search() Successfully queried Images by filter criteria")
	secLog.Infof("%s: Flavor Searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return model.ImageCollection{Images: images}, http.StatusOK, nil
}

func (icon *ImageController) UpdateAssociatedFlavor(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/image_controller:UpdateAssociatedFlavor() Entering")
	defer defaultLog.Trace("controllers/image_controller:UpdateAssociatedFlavor() Leaving")

	imageUUID, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:UpdateAssociatedFlavor() %s : Invalid image UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to update image - Invalid image UUID format"}
	}

	flavorUUID, err := uuid.Parse(mux.Vars(r)["flavorID"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:UpdateAssociatedFlavor() %s : Invalid flavor UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to update image - Invalid flavor UUID format"}
	}

	if err := icon.IStore.Update(imageUUID, flavorUUID); err != nil {
		defaultLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).WithError(err).Errorf("controllers/images_controller:UpdateAssociatedFlavor() %s : Failed to add new Flavor association", message.AppRuntimeErr)
		defaultLog.Tracef("%+v", err)
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.Errorf("controllers/image_controller:UpdateAssociatedFlavor() Flavor does not exist in database")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor does not exist in database"}
		} else if err == postgres.ErrImageDoesNotExist {
			defaultLog.Errorf("controllers/image_controller:UpdateAssociatedFlavor() Image does not exist in database")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Image does not exist in database to update"}
		}
		defaultLog.Errorf("controllers/image_controller: Failed to update image/flavor association - Backend error")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update image/flavor association - Backend error"}
	}

	defaultLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).Info("controllers/images_controller:UpdateAssociatedFlavor() Successfully added new Flavor association")
	secLog.Infof("%s: Flavor associated with image Updated by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return nil, http.StatusOK, nil
}

func (icon *ImageController) GetAssociatedFlavor(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("controllers/images_controller:GetAssociatedFlavor() Entering")
	defer defaultLog.Trace("controllers/images_controller:GetAssociatedFlavor() Leaving")

	imageUUID, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavor() %s : Invalid UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - Invalid image UUID format"}
	}

	flavorUUID, err := uuid.Parse(mux.Vars(r)["flavorID"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavor() %s : Invalid flavor UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - Invalid image UUID format"}
	}
	var flavor *model.Image

	flavor, err = icon.IStore.RetrieveFlavor(imageUUID, flavorUUID)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavor() %s : Failed to retrieve associated flavors for image", message.AppRuntimeErr)
			secLog.Debug(err.Error())
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - No flavor associated with given image UUID"}
		} else {
			secLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).WithError(err).Errorf("controllers/images_controller:GetAssociatedFlavor() %s : Failed to retrieve associated flavors for image", message.AppRuntimeErr)
			secLog.Tracef("%+v", err)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve associated flavor - backend error"}
		}
	}

	defaultLog.WithField("imageUUID", imageUUID).WithField("flavorUUID", flavorUUID).Info("controllers/images_controller:GetAssociatedFlavor() Successfully retrieved associated Flavor")
	secLog.Infof("%s: Flavor associated with image Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavor, http.StatusOK, nil
}

func (icon *ImageController) GetAllAssociatedFlavors(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/images_controller:GetAllAssociatedFlavors() Entering")
	defer defaultLog.Trace("controllers/images_controller:GetAllAssociatedFlavors() Leaving")

	uuid, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		secLog.WithError(err).Errorf("controllers/images_controller:GetAllAssociatedFlavors() %s : Invalid UUID format", message.InvalidInputProtocolViolation)
		secLog.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve associated flavors - Invalid image UUID format"}
	}

	var flavors *model.Image
	flavors, err = icon.IStore.RetrieveFlavors(uuid)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithField("uuid", uuid).WithError(err).Errorf("controllers/images_controller:GetAllAssociatedFlavors() %s : Failed to retrieve associated flavors for image", message.AppRuntimeErr)
			defaultLog.Tracef("%+v", err)
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Failed to retrieve associated flavors - No Flavor found for Image"}
		} else {
			defaultLog.WithField("uuid", uuid).WithError(err).Errorf("controllers/images_controller:GetAllAssociatedFlavors() %s : Failed to retrieve associated flavors for image", message.AppRuntimeErr)
			defaultLog.Tracef("%+v", err)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve associated flavors - backend error"}
		}
	}

	defaultLog.WithField("uuid", uuid).Info("controllers/images_controller:GetAllAssociatedFlavors() Successfully retrieved associated flavors for image")
	secLog.Infof("%s: Flavor associated with image Retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavors, http.StatusOK, nil
}
