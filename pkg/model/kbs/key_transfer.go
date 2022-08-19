/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package kbs

type KeyTransferResponse struct {
	WrappedKey string `json:"wrapped_key"`
	WrappedSWK string `json:"wrapped_swk,omitempty"`
}
