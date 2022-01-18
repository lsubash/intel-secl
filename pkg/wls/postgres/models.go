/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/verifier/workload"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"time"
)

// Define all struct types here
type (
	PGFlavorContent    wls.Image
	PGTrustReport      workload.InstanceTrustReport
	PGReportSignedData crypt.SignedData

	flavor struct {
		ID         uuid.UUID       `gorm:"type:uuid;primary_key;"`
		CreatedAt  time.Time       `gorm:"column:created;not null"`
		Label      string          `gorm:"unique;not null"`
		FlavorPart string          `gorm:"not null"`
		Content    PGFlavorContent `json:"flavor" sql:"type:JSONB"`
		Signature  string          `json:"signature"`
	}

	imageFlavor struct {
		ImageId  uuid.UUID `gorm:"type:uuid;primary_key;"`
		FlavorId uuid.UUID `gorm:"type:uuid REFERENCES flavor(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;unique;unique_index:idx_image_flavor;"`
	}

	report struct {
		ID          uuid.UUID          `gorm:"type:uuid;primary_key;"`
		CreatedAt   time.Time          `gorm:"column:created;not null"`
		Expiration  time.Time          `gorm:"column:expiration;not null"`
		InstanceID  string             `gorm:"type:uuid;not null"`
		Saml        string             `gorm:"column:saml;not null"`
		TrustReport PGTrustReport      `json:"trust_report" sql:"type:JSONB"`
		SignedData  PGReportSignedData `json:"signed_data" sql:"type:JSONB"`
	}
)

func (fl PGFlavorContent) Value() (driver.Value, error) {
	return json.Marshal(fl)
}

func (fl *PGFlavorContent) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGFlavorContent_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &fl)
}

func (rsd PGReportSignedData) Value() (driver.Value, error) {
	return json.Marshal(rsd)
}

func (rsd *PGReportSignedData) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGReportSignedData_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &rsd)
}

func (r PGTrustReport) Value() (driver.Value, error) {
	return json.Marshal(r)
}

func (r *PGTrustReport) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGTrustReport_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &r)
}
