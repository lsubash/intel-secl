/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import (
	"fmt"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/wpm/constants"
)

func TestGetVersion(t *testing.T) {
	Version = "1"
	GitHash = "abc1234"
	BuildDate = "01-01-1990"

	expected := fmt.Sprintf("Service Name: %s\n", constants.ExtendedServiceName)
	expected = expected + fmt.Sprintf("Version: %s-%s\n", Version, GitHash)
	expected = expected + fmt.Sprintf("Build Date: %s\n", BuildDate)

	tests := []struct {
		name string
		want string
	}{
		{
			name: "Valid test",
			want: expected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetVersion(); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
