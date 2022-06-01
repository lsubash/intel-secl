/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionController_GetVersion(t *testing.T) {

	responseWri := httptest.NewRecorder()

	type args struct {
		w   http.ResponseWriter
		in1 *http.Request
	}
	tests := []struct {
		name       string
		controller VersionController
		args       args
	}{
		{
			name:       "Should pass for getting version",
			controller: VersionController{},
			args: args{
				w:   responseWri,
				in1: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := VersionController{}
			controller.GetVersion(tt.args.w, tt.args.in1)
		})
	}
}
