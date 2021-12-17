/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package workload

import "github.com/intel-secl/intel-secl/v5/pkg/lib/common/pkg/instance"

// ImageTrustReport is a record that indicates trust status of an image
type InstanceTrustReport struct {
	Manifest   instance.Manifest `json:"instance_manifest"`
	PolicyName string            `json:"policy_name"`
	Results    []Result          `json:"results"`
	Trusted    bool              `json:"trusted"`
}
