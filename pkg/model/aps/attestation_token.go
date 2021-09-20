/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aps

import "github.com/google/uuid"

type AttestationTokenRequest struct {
	Quote     string      `json:"quote"`
	UserData  string      `json:"user_data"`
	PolicyIds []uuid.UUID `json:"policy_ids"`
}

type SignedNonce struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type AttestationTokenClaim struct {
	MrSeam          string      `json:"mr_seam,omitempty"`
	MrEnclave       string      `json:"mr_enclave,omitempty"`
	MrSigner        string      `json:"mr_signer,omitempty"`
	MrSignerSeam    string      `json:"mr_signer_seam,omitempty"`
	MrConfigId      string      `json:"mr_config_id,omitempty"`
	IsvProductId    uint16      `json:"isv_product_id,omitempty"`
	MRTD            string      `json:"mr_td,omitempty"`
	RTMR0           string      `json:"rtmr0,omitempty"`
	RTMR1           string      `json:"rtmr1,omitempty"`
	RTMR2           string      `json:"rtmr2,omitempty"`
	RTMR3           string      `json:"rtmr3,omitempty"`
	SeamSvn         uint8       `json:"seam_svn, omitempty"`
	IsvSvn          uint16      `json:"isv_svn,omitempty"`
	EnclaveHeldData string      `json:"enclave_held_data,omitempty"`
	PolicyIds       []uuid.UUID `json:"policy_ids"`
	TcbStatus       string      `json:"tcb_status"`
	Tee             string      `json:"tee"`
	Version         string      `json:"ver"`
}
