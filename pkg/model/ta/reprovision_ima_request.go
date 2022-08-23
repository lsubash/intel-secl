/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

// json request format sent from HVS...
// {
//     "files"             : ["file1","file2","file3"]
// }
type ReprovisionImaRequest struct {
	Files []string `json:"files"`
}
