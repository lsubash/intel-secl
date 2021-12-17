/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package workload

import (
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
)

const EncryptionMatchesName = "EncryptionMatches"

func newEncryptionMatches(imageType string, encryptionRequired bool) *wls.EncryptionMatches {
	return &wls.EncryptionMatches{
		EncryptionMatchesName,
		[]string{imageType},
		wls.ExpectedEncryption{
			"encryption_required",
			encryptionRequired,
		},
	}
}
