/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package postgres

import (
	"github.com/google/uuid"
	flvr "github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"time"
)

type FlavorStore struct {
	Store *DataStore
}

func NewFlavorStore(store *DataStore) *FlavorStore {
	return &FlavorStore{store}
}

//Create creates new Signed Image Flavor
func (fs *FlavorStore) Create(f *flvr.SignedImageFlavor) (*flvr.SignedImageFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Create() Leaving")

	dbf := flavor{
		ID:         f.ImageFlavor.Meta.ID,
		CreatedAt:  time.Now(),
		Label:      f.ImageFlavor.Meta.Description.Label,
		FlavorPart: f.ImageFlavor.Meta.Description.FlavorPart,
		Content:    PGFlavorContent(f.ImageFlavor),
		Signature:  f.Signature,
	}

	if err := fs.Store.Db.Create(&dbf).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Create() failed to create flavor")
	}
	return f, nil
}

//Search can be done with 2 options, FlavorID or Label
//it returns Flavor Associated with FlavorID or Label
func (fs *FlavorStore) Search(flavorFilter *model.FlavorFilter) ([]flvr.SignedImageFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Search() Leaving")

	var tx *gorm.DB

	tx = fs.Store.Db.Table("flavor f").Select("f.content, f.signature")
	tx = buildFlavorSearchQuery(tx, flavorFilter)

	if tx == nil {
		return nil, errors.New("postgres/flavor_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in Flavor Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("postgres/flavor_store:Search() Error closing rows")
		}
	}()

	var flvrResultSet = []flvr.SignedImageFlavor{}
	for rows.Next() {
		flavor := flvr.SignedImageFlavor{}
		if err := rows.Scan((*PGFlavorContent)(&flavor.ImageFlavor), &flavor.Signature); err != nil {
			return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to scan record")
		}
		flvrResultSet = append(flvrResultSet, flavor)
	}

	return flvrResultSet, nil
}

// Retrieve return Flavor with given ID
func (fs *FlavorStore) Retrieve(flavorId uuid.UUID) (*flvr.SignedImageFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Retrieve() Leaving")

	sf := flvr.SignedImageFlavor{}
	row := fs.Store.Db.Model(flavor{}).Select("content, signature").Where(&flavor{ID: flavorId}).Row()
	if err := row.Scan((*PGFlavorContent)(&sf.ImageFlavor), &sf.Signature); err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Retrieve() - Could not scan record ")
	}
	return &sf, nil
}

// Delete deletes flavors with given flavor ID
func (fs *FlavorStore) Delete(flavorId uuid.UUID) error {
	defaultLog.Trace("postgres/flavor_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Delete() Leaving")

	dbFlavor := flavor{
		ID: flavorId,
	}
	if err := fs.Store.Db.Where(&dbFlavor).Delete(&dbFlavor).Error; err != nil {
		return errors.Wrap(err, "postgres/flavor_store:Delete() failed to delete Flavor")
	}
	return nil
}

// buildFlavorSearchQuery helper function to build the query object for a Flavor search.
func buildFlavorSearchQuery(tx *gorm.DB, flavorFilter *model.FlavorFilter) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:buildFlavorSearchQuery() Entering")
	defer defaultLog.Trace("postgres/flavor_store:buildFlavorSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	if flavorFilter == nil {
		defaultLog.Info("postgres/flavor_store:buildFlavorSearchQuery() No criteria specified in search query" +
			". Returning all rows.")
		return tx
	}

	// Flavor ID
	if flavorFilter.FlavorID != uuid.Nil {
		tx = tx.Select("content, signature").Where("id = ?", flavorFilter.FlavorID.String())
	}

	// Flavor label
	if flavorFilter.Label != "" {
		tx = tx.Select("content, signature").Where("label = ?", flavorFilter.Label)
	}
	return tx
}
