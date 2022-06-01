/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import "testing"

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Get version should be successful",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = GetVersion()
		})
	}
}
