/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/pkg/errors"
)

//RetrieveFlavorsV1 returns all the flavors associated with given image id
func (i *ImageStore) RetrieveFlavorsV1(imageId uuid.UUID) ([]wls.SignedImageFlavor, error) {
	defaultLog.Trace("postgres/image_store_v1:RetrieveFlavorsV1() Entering")
	defer defaultLog.Trace("postgres/image_store_v1:RetrieveFlavorsV1() Leaving")

	imgf, err := i.Retrieve(imageId)
	if err != nil {
		defaultLog.Errorf("postgres/image_store_v1:RetrieveFlavorsV1() failed to retreive image id")
		return nil, errors.Wrap(err, "Failed to retrieve image")
	}
	var flavorResultSet []wls.SignedImageFlavor
	for _, flavorId := range imgf.FlavorIDs {
		var sf wls.SignedImageFlavor
		row := i.Store.Db.Model(&flavor{}).Select("content,signature").Where("id=?", flavorId).Row()
		if err := row.Scan((*PGFlavorContent)(&sf.ImageFlavor), &sf.Signature); err != nil {
			return nil, errors.Wrap(err, "postgres/image_store_v1:RetrieveFlavorsV1() - Could not scan record ")
		}
		flavorResultSet = append(flavorResultSet, sf)
	}
	return flavorResultSet, nil
}

//RetrieveFlavorV1 retrieves flavor with given image id and flavor id
func (i *ImageStore) RetrieveFlavorV1(imageUUID uuid.UUID, flavorUUID uuid.UUID) (*wls.SignedImageFlavor, error) {
	defaultLog.Trace("postgres/image_store_v1:RetrieveFlavorV1() Entering")
	defer defaultLog.Trace("postgres/image_store_v1:RetrieveFlavorV1() Leaving")

	sf := wls.SignedImageFlavor{}
	row := i.Store.Db.Model(&flavor{}).Select("content,signature").Where("id=?", flavorUUID).Row()
	if err := row.Scan((*PGFlavorContent)(&sf.ImageFlavor), &sf.Signature); err != nil {
		return nil, errors.Wrap(err, "postgres/image_store_v1:RetrieveFlavorV1() - Could not scan record ")
	}
	return &sf, nil
}
