/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package admission_controller

import (
	"testing"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/config"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/admission-controller/constants"
)

func TestStartServer(t *testing.T) {
	type args struct {
		router                    *mux.Router
		admissionControllerConfig config.Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid case should pass in starting the server",
			args: args{
				router:                    mux.NewRouter(),
				admissionControllerConfig: config.Config{}},
			wantErr: false,
		},
		{
			name: "Valid case should pass in starting the server and httplog file should be opened",
			args: args{
				router:                    mux.NewRouter(),
				admissionControllerConfig: config.Config{}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.name == "Valid case should pass in starting the server and httplog file should be opened" {
				constants.HttpLogFile = "httplog.log"
			}

			if err := StartServer(tt.args.router, tt.args.admissionControllerConfig); (err != nil) != tt.wantErr {
				t.Errorf("StartServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
