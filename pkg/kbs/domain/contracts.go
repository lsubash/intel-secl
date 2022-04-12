/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
)

type (
	KeyStore interface {
		Create(*models.KeyAttributes) (*models.KeyAttributes, error)
		Retrieve(uuid.UUID) (*models.KeyAttributes, error)
		Delete(uuid.UUID) error
		Search(criteria *models.KeyFilterCriteria) ([]models.KeyAttributes, error)
	}

	KeyTransferPolicyStore interface {
		Create(attributes *kbs.KeyTransferPolicy) (*kbs.KeyTransferPolicy, error)
		Retrieve(uuid.UUID) (*kbs.KeyTransferPolicy, error)
		Update(attributes *kbs.KeyTransferPolicy) (*kbs.KeyTransferPolicy, error)
		Delete(uuid.UUID) error
		Search(criteria *models.KeyTransferPolicyFilterCriteria) ([]kbs.KeyTransferPolicy, error)
	}

	CertificateStore interface {
		Create(certificate *kbs.Certificate) (*kbs.Certificate, error)
		Retrieve(uuid.UUID) (*kbs.Certificate, error)
		Delete(uuid.UUID) error
		Search(criteria *models.CertificateFilterCriteria) ([]kbs.Certificate, error)
	}
)
