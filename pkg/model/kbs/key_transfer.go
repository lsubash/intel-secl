/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package kbs

type KeyTransferRequest struct {
	Quote            string `json:"quote,omitempty"`
	AttestationToken string `json:"attestation_token,omitempty"`
	UserData         string `json:"user_data"`
}

type KeyTransferResponse struct {
	WrappedKey string `json:"wrapped_key"`
	WrappedSWK string `json:"wrapped_swk,omitempty"`
}
