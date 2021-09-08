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
