/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

type UpdateImaMeasurementsReq struct {
	ConnectionString string   `json:"connection_string"`
	Files            []string `json:"files"`
}
