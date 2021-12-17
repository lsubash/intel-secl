/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"database/sql"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type ImageStore struct {
	Store *DataStore
}

func NewImageStore(store *DataStore) *ImageStore {
	return &ImageStore{store}
}

var (
	ErrImageAssociationAlreadyExists        = errors.New("image association with UUID already exists")
	ErrImageAssociationFlavorDoesNotExist   = errors.New("one or more FlavorID's does not exist in the database")
	ErrImageAssociationDuplicateFlavor      = errors.New("flavor with UUID already associated with image")
	ErrImageAssociationDuplicateImageFlavor = errors.New("image can only be associated with one flavor with FlavorPart = IMAGE")
	ErrImageDoesNotExist                    = errors.New("image does not exist in database")
)

//Create creates new Image Flavor Association
func (i *ImageStore) Create(img *model.Image) error {
	defaultLog.Trace("postgres/image_store:Create() Entering")
	defer log.Trace("postgres/image_store:Create() Leaving")

	var ie imageFlavor

	ie = imageFlavor{
		ImageId: img.ID,
	}

	//check those flavor ids actually exist in the flavor table
	var flavorEntities []flavor
	i.Store.Db.Find(&flavorEntities, "id in (?)", img.FlavorIDs)
	if len(flavorEntities) != len(img.FlavorIDs) {
		// some flavor ID's dont exist
		return ErrImageAssociationFlavorDoesNotExist
	}

	ie.FlavorId = img.FlavorIDs[0]
	err := i.Store.Db.Create(&ie).Error
	if err != nil {
		return errors.Wrap(err, "postgres/image_store: Create() Failed to create image")
	}
	if len(img.FlavorIDs) > 1 {
		defaultLog.Warning("postgres/image_store:Create() Only one flavor can be associated with an image, rest of the flavors will be ignored")
		return errors.New("Only one flavor can be associated with an image")
	}
	defaultLog.Info("postgres/image_store:Create() Successfully Create image flavor association")
	return nil
}

//DeleteImageFlavorAssociation deletes image flavor association with given image id and flavor id
func (i *ImageStore) DeleteImageFlavorAssociation(imageUUID uuid.UUID, flavorUUID uuid.UUID) error {
	log.Trace("postgres/image_store: DeleteImageFlavorAssociation() Entering")
	defer log.Trace("postgres/image_store: DeleteImageFlavorAssociation() Leaving")

	re := imageFlavor{
		ImageId:  imageUUID,
		FlavorId: flavorUUID,
	}

	err := i.Store.Db.First(&re, "image_id = ? and flavor_id = ?", re.ImageId, re.FlavorId).Error
	if gorm.IsRecordNotFoundError(err) {
		return errors.Wrap(err, "no rows in result set")
	} else if err != nil {
		return errors.Wrap(err, "Error while retrieving the DB records")
	}

	if err := i.Store.Db.Model(&imageFlavor{}).Where("image_id = ? and flavor_id=? ", imageUUID.String(), flavorUUID.String()).Delete(&re).Error; err != nil {
		return errors.Wrap(err, "postgres/report_store: Delete() failed to delete ImageFlavorAssociation")
	}
	return nil
}

//Delete deletes image with given image id
func (i *ImageStore) Delete(imageId uuid.UUID) error {
	defaultLog.Trace("postgres/image_store:Delete() Entering")
	defer defaultLog.Trace("postgres/image_store:Delete() Leaving")
	dbImage := imageFlavor{
		ImageId: imageId,
	}

	err := i.Store.Db.First(&dbImage, "image_id = ?", dbImage.ImageId).Error
	defaultLog.Errorf("Delete() Error is %v", err)
	if gorm.IsRecordNotFoundError(err) {
		return errors.Wrap(err, "no rows in result set")
	}

	if err := i.Store.Db.Delete(&dbImage).Where(&dbImage).Error; err != nil {
		return errors.Wrap(err, "postgres/image_store:Delete() failed to delete Flavor")
	}
	return nil
}

//Retrieve retrieves image flavor association with the given image id
func (i *ImageStore) Retrieve(imageId uuid.UUID) (*model.Image, error) { //To Retrieve all the flavor id's associated with that image id
	defaultLog.Trace("postgres/image_store:RetrieveImageByID() Entering")
	defer defaultLog.Trace("postgres/image_store:RetrieveImageByID() Leaving")

	rows, err := i.Store.Db.Table("image_flavor").Where("image_id = ?", imageId).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:RetrieveImageByID() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	var img model.Image
	var imgflvr imageFlavor
	for rows.Next() {
		if err := rows.Scan(&imgflvr.ImageId, &imgflvr.FlavorId); err != nil {
			return nil, errors.Wrap(err, "postgres/image_store: RetrieveImageByID() failed to scan record")
		}
		img.ID = imgflvr.ImageId
		img.FlavorIDs = append(img.FlavorIDs, imgflvr.FlavorId)
	}

	if len(img.FlavorIDs) == 0 {
		defaultLog.Infof("postgres/image_store: RetrieveImageByID() No record found in database %v", img)
		return nil, errors.New("no rows in result set")
	}
	return &img, nil
}

//RetrieveAssociatedFlavorByFlavorPart retrieves flavor with given flavor_part and image id
func (i *ImageStore) RetrieveAssociatedFlavorByFlavorPart(imageUUID uuid.UUID, flavorPart string) (*wls.SignedImageFlavor, error) {
	defaultLog.Trace("postgres/image_store:RetrieveAssociatedFlavorByFlavorPart() Entering")
	defer defaultLog.Trace("repository/postgres/image_store:RetrieveAssociatedFlavorByFlavorPart() Leaving")

	sf := wls.SignedImageFlavor{}
	row := i.Store.Db.Model(&flavor{}).Select("flavor.content,flavor.signature").Joins("INNER JOIN image_flavor imgf ON flavor.id = imgf.flavor_id").Where("imgf.image_id=? AND flavor.flavor_part=?", imageUUID, flavorPart).Row()
	if err := row.Scan((*PGFlavorContent)(&sf.ImageFlavor), &sf.Signature); err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:RetrieveAssociatedFlavorByFlavorPart() - Could not scan record ")
	}
	return &sf, nil
}

//RetrieveImageFlavor retrieves flavor with given image id
func (i *ImageStore) RetrieveImageFlavor(imageUUID uuid.UUID) (*wls.SignedImageFlavor, error) {
	defaultLog.Trace("postgres/image_store:RetrieveImageFlavor() Entering")
	defer defaultLog.Trace("postgres/image_store:RetrieveImageFlavor() Leaving")

	sf := wls.SignedImageFlavor{}
	row := i.Store.Db.Model(&flavor{}).Select("flavor.content,flavor.signature").Joins("INNER JOIN image_flavor imgf ON flavor.id = imgf.flavor_id").Where("imgf.image_id=? AND (flavor.flavor_part=? OR flavor.flavor_part=?)", imageUUID, "IMAGE", "CONTAINER_IMAGE").Row()
	if err := row.Scan((*PGFlavorContent)(&sf.ImageFlavor), &sf.Signature); err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:RetrieveImageFlavor() - Could not scan record ")
	}
	return &sf, nil
}

//Search fetches image for the given filter criteria
func (i *ImageStore) Search(filter model.ImageFilter) ([]model.Image, error) {
	defaultLog.Trace("postgres/image_store:Search() Entering")
	defer defaultLog.Trace("postgres/image_store:Search() Leaving")

	var imgResultSet []model.Image
	var rows *sql.Rows
	var err error
	var tx *gorm.DB
	tx = i.Store.Db.Model(&imageFlavor{})

	if filter.ImageID != uuid.Nil {
		tx = tx.Where("image_id = ?", filter.ImageID.String())
	}
	if filter.FlavorID != uuid.Nil {
		tx = tx.Where("flavor_id = ?", filter.FlavorID.String())
	}

	rows, err = tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("postgres/image_store:Search() Error closing rows")
		}
	}()

	var img model.Image
	var imgflvr imageFlavor
	for rows.Next() {
		if err := rows.Scan(&imgflvr.ImageId, &imgflvr.FlavorId); err != nil {
			return nil, errors.Wrap(err, "postgres/image_store:Search() failed to scan record")
		}
		img.ID = imgflvr.ImageId
		img.FlavorIDs = append(img.FlavorIDs, imgflvr.FlavorId)
	}
	imgResultSet = append(imgResultSet, img)
	return imgResultSet, nil
}

//Update updates the new association with the already existing image id
func (i *ImageStore) Update(imageUUID uuid.UUID, flavorUUID uuid.UUID) error {
	defaultLog.Trace("postgres/image_store:Update() Entering")
	defer defaultLog.Trace("postgres/image_store:Update() Leaving")

	dbImage := imageFlavor{
		ImageId: imageUUID,
	}

	err := i.Store.Db.First(&dbImage, "image_id = ?", imageUUID).Error
	if gorm.IsRecordNotFoundError(err) {
		return ErrImageDoesNotExist
	} else if err != nil {
		return errors.New("postgres/image_store: Update() error while retrieving the data")
	}

	dbFlavor := flavor{
		ID: flavorUUID,
	}
	err = i.Store.Db.First(&dbFlavor, "id = ?", flavorUUID).Error
	if gorm.IsRecordNotFoundError(err) {
		defaultLog.Error("postgres/image_store: Update() Given flavor doesn't exist")
		return errors.Wrap(err, "no rows in result set, Given flavor doesn't exist")
	} else if err != nil {
		return errors.New("postgres/image_store: Update() error while retrieving the data")
	}

	err = i.Store.Db.Model(&imageFlavor{}).Where("image_id=?", imageUUID).Update("flavor_id", flavorUUID).Error
	if err != nil {
		return errors.Wrap(err, "postgres/image_store: Update() Failed to update association image")
	}
	return nil
}

//RetrieveFlavors retrieves all flavor ids associated with given image id
func (i *ImageStore) RetrieveFlavors(imageId uuid.UUID) (*model.Image, error) {
	defaultLog.Trace("postgres/image_store:RetrieveFlavors() Entering")
	defer defaultLog.Trace("postgres/image_store:RetrieveFlavors() Leaving")

	rows, err := i.Store.Db.Table("image_flavor").Where("image_id = ?", imageId.String()).Rows()
	if err != nil {
		defaultLog.Errorf("RetrieveFlavors() error in Rows() %v", err)
		return nil, errors.Wrap(err, "postgres/flavor_store:Search()  no rows in result set")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("postgres/image_store:RetrieveFlavors() Error closing rows")
		}
	}()

	var img model.Image
	img.ID = imageId
	var imgflvr imageFlavor

	for rows.Next() {
		if err := rows.Scan(&imgflvr.ImageId, &imgflvr.FlavorId); err != nil {
			return nil, errors.Wrap(err, "postgres/image_store:Search() failed to scan record")
		}
		img.FlavorIDs = append(img.FlavorIDs, imgflvr.FlavorId)
	}

	if len(img.FlavorIDs) == 0 {
		defaultLog.Infof("postgres/image_store: RetrieveImageByID() No record found in database %v", img)
		return nil, errors.New("postgres/image_store() no rows in result set")
	}

	return &img, nil
}

//RetrieveFlavor retrieves flavor id associated with given image id
func (i *ImageStore) RetrieveFlavor(imageUUID uuid.UUID, flavorUUID uuid.UUID) (*model.Image, error) {
	defaultLog.Trace("postgres/image_store:RetrieveFlavor() Entering")
	defer defaultLog.Trace("postgres/image_store:RetrieveFlavor() Leaving")

	var ie imageFlavor
	row := i.Store.Db.Model(&imageFlavor{}).Where("image_id = ? and flavor_id = ?", imageUUID, flavorUUID).Row()
	if err := row.Scan(&ie.ImageId, &ie.FlavorId); err != nil {
		defaultLog.Errorf("RetrieveFlavor() error in row() %v", err)
		return nil, errors.Wrap(err, "postgres/flavor_store:RetrieveFlavor() - Could not scan record ")
	}

	var imgf model.Image
	imgf.ID = ie.ImageId
	imgf.FlavorIDs = append(imgf.FlavorIDs, ie.FlavorId)

	if len(imgf.FlavorIDs) == 0 {
		defaultLog.Infof("postgres/image_store: RetrieveImageByID() No record found in database %v", imgf)
		return nil, errors.New("postgres/image_store() no rows in result set")
	}

	return &imgf, nil
}
