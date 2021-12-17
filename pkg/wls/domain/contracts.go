/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package domain

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
)

type (
	FlavorStore interface {
		Create(flavor *wls.SignedImageFlavor) (*wls.SignedImageFlavor, error)
		Retrieve(uuid.UUID) (*wls.SignedImageFlavor, error)
		Search(*model.FlavorFilter) ([]wls.SignedImageFlavor, error)
		Delete(uuid.UUID) error
	}

	ReportStore interface {
		Create(report *model.Report) (*model.Report, error)
		Retrieve(uuid.UUID) (*model.Report, error)
		Search(filter *model.ReportFilter) ([]model.Report, error)
		Delete(uuid.UUID) error
	}

	ImageStore interface {
		Create(image *model.Image) error
		Delete(uuid uuid.UUID) error
		DeleteImageFlavorAssociation(imageUUID uuid.UUID, flavorUUID uuid.UUID) error
		Retrieve(uuid uuid.UUID) (*model.Image, error)
		RetrieveAssociatedFlavorByFlavorPart(imageUUID uuid.UUID, flavorPart string) (*wls.SignedImageFlavor, error)
		RetrieveImageFlavor(imageUUID uuid.UUID) (*wls.SignedImageFlavor, error)
		Search(filter model.ImageFilter) ([]model.Image, error)
		Update(imageUUID uuid.UUID, flavorUUID uuid.UUID) error
		RetrieveFlavors(uuid uuid.UUID) (*model.Image, error)
		RetrieveFlavor(imageUUID uuid.UUID, flavorUUID uuid.UUID) (*model.Image, error)
		RetrieveFlavorV1(imageUUID uuid.UUID, flavorUUID uuid.UUID) (*wls.SignedImageFlavor, error)
		RetrieveFlavorsV1(uuid uuid.UUID) ([]wls.SignedImageFlavor, error)
	}
)
