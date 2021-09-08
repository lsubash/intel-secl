/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
)

// KeyTransferPolicy - used in key transfer policy create request and response.
type KeyTransferPolicy struct {
	// swagger:strfmt uuid
	ID              uuid.UUID  `json:"id,omitempty"`
	CreatedAt       time.Time  `json:"created_at,omitempty"`
	AttestationType []string   `json:"attestation_type"`
	TDX             *TdxPolicy `json:"tdx,omitempty"`
	SGX             *SgxPolicy `json:"sgx,omitempty"`
}

type TdxPolicy struct {
	Attributes *TdxAttributes `json:"attributes,omitempty"`
	// swagger:strfmt uuid
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type TdxAttributes struct {
	MrSignerSeam       []string `json:"mr_signer_seam,omitempty"`
	MrSeam             []string `json:"mr_seam,omitempty"`
	SeamSvn            *uint8   `json:"seam_svn,omitempty"`
	MRTD               []string `json:"mr_td,omitempty"`
	RTMR0              string   `json:"rtmr0,omitempty"`
	RTMR1              string   `json:"rtmr1,omitempty"`
	RTMR2              string   `json:"rtmr2,omitempty"`
	RTMR3              string   `json:"rtmr3,omitempty"`
	EnforceTCBUptoDate *bool    `json:"enforce_tcb_upto_date,omitempty"`
}

type SgxPolicy struct {
	Attributes *SgxAttributes `json:"attributes,omitempty"`
	// swagger:strfmt uuid
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type SgxAttributes struct {
	MrSigner             []string `json:"mr_signer,omitempty"`
	IsvProductId         []uint16 `json:"isv_prod_id,omitempty"`
	IsvExtendedProductId []string `json:"isv_ext_prod_id,omitempty"`
	MrEnclave            []string `json:"mr_enclave,omitempty"`
	ConfigSVN            *int16   `json:"config_svn,omitempty"`
	IsvSvn               *uint16  `json:"isv_svn,omitempty"`
	ConfigId             []string `json:"config_id,omitempty"`
	ClientPermissions    []string `json:"client_permissions,omitempty"`
	EnforceTCBUptoDate   *bool    `json:"enforce_tcb_upto_date,omitempty"`
}
