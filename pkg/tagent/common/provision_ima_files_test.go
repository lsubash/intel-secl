/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"os"
	"testing"

	taModel "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/config"
)

const testImaReprovisionFilePath = "../test/resources/etc/trustagent"

func Test_requestHandlerImpl_ProvisionImaFiles(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	var inputFiles = []string{"file1", testImaReprovisionFilePath}
	os.MkdirAll(testImaReprovisionFilePath, os.ModePerm)
	defer DeleteCommonDir(testImaReprovisionFilePath)
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		reprovisionFilePath string
		provisionRequest    *taModel.ReprovisionImaRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Invalid reprovision file path",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				reprovisionFilePath: "",
				provisionRequest:    &taModel.ReprovisionImaRequest{Files: inputFiles},
			},
			wantErr: true,
		},
		{
			name: "Invalid provision request",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				reprovisionFilePath: "reprovision-file-list.txt",
				provisionRequest:    &taModel.ReprovisionImaRequest{Files: []string{"jkl<> \u001f \0000/000>"}},
			},
			wantErr: true,
		},
		{
			name: "Valid Provision Ima files request",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				reprovisionFilePath: testImaReprovisionFilePath + "/reprovision-file-list.txt",
				provisionRequest:    &taModel.ReprovisionImaRequest{Files: inputFiles},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			if err := handler.ProvisionImaFiles(tt.args.reprovisionFilePath, tt.args.provisionRequest); (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.ProvisionImaFiles() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
