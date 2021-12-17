/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/verifier/workload"
	"time"
)

// Report is an alias to verifier.workload.VMTrustReport
type Report struct {
	ID uuid.UUID `json:"id,omitempty"`
	workload.InstanceTrustReport
	crypt.SignedData
}

// ReportFilter struct defines all the filter criterias to query the reports table
type ReportFilter struct {
	InstanceID   uuid.UUID
	ReportID     uuid.UUID
	HardwareUUID uuid.UUID
	LatestPerVM  bool
	NumberOfDays int
	FromDate     time.Time
	ToDate       time.Time
}
