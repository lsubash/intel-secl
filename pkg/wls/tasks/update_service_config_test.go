/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"io"
	"testing"

	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
)

func TestUpdateServiceConfigSetName(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		HVSApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		ConsoleWriter io.Writer
	}
	type args struct {
		n string
		e string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Valid case should pass",
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				HVSApiUrl:     tt.fields.HVSApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			uc.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestUpdateServiceConfigPrintHelp(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		HVSApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "Valid case should pass",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				HVSApiUrl:     tt.fields.HVSApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			w := &bytes.Buffer{}
			uc.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestUpdateServiceConfigRun(t *testing.T) {

	hvsApiUrl := "http://localhost:1338/hvs/v2/"
	aasApiUrl := "http://localhost:1336/aas/v1/"

	appConfig := &config.Configuration{}

	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		HVSApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Should fail for WLS_SERVICE_USERNAME is not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "",
				},
			},
			wantErr: true,
		},
		{
			name: "Should fail for WLS_SERVICE_PASSWORD is not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "TestUser",
					Password: "",
				},
			},
			wantErr: true,
		},
		{
			name: "Should fail for AAS_BASE_URL is not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "TestUser",
					Password: "TestUserPassword",
				},
			},
			wantErr: true,
		},
		{
			name: "Should fail for HVS_BASE_URL is not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "TestUser",
					Password: "TestUserPassword",
				},
				AASApiUrl: aasApiUrl,
			},
			wantErr: true,
		},
		{
			name: "Updating service configuration should be successful",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "TestUser",
					Password: "TestUserPassword",
				},
				AASApiUrl:    aasApiUrl,
				HVSApiUrl:    hvsApiUrl,
				ServerConfig: commConfig.ServerConfig{},
				AppConfig:    &appConfig,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				HVSApiUrl:     tt.fields.HVSApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			if err := uc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfigValidate(t *testing.T) {

	hvsApiUrl := "http://localhost:1338/hvs/v2/"
	aasApiUrl := "http://localhost:1336/aas/v1/"

	appConfig := &config.Configuration{}

	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		HVSApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Should fail for WLS username is not set in the configuration",
			fields: fields{
				AppConfig: &appConfig,
			},
			wantErr: true,
		},
		{
			name: "Should fail for WLS password is not set in the configuration",
			fields: fields{
				AppConfig: &appConfig,
			},
			wantErr: true,
		},
		{
			name: "Should fail for AAS API url is not set in the configuration",
			fields: fields{
				AppConfig: &appConfig,
			},
			wantErr: true,
		},
		{
			name: "Should fail for HVS API url is not set in the configuration",
			fields: fields{
				AppConfig: &appConfig,
			},
			wantErr: true,
		},
		{
			name: "Should fail for Invalid port number",
			fields: fields{
				AppConfig: &appConfig,
			},
			wantErr: true,
		},
		{
			name: "Validation should be successful",
			fields: fields{
				AppConfig: &appConfig,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				HVSApiUrl:     tt.fields.HVSApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}

			if tt.name == "Should fail for WLS password is not set in the configuration" {
				appConfig.WLS.Username = "Sampleuser"
			} else if tt.name == "Should fail for AAS API url is not set in the configuration" {
				appConfig.WLS.Password = "SampleuserPassword"
			} else if tt.name == "Should fail for HVS API url is not set in the configuration" {
				appConfig.AASApiUrl = aasApiUrl
			} else if tt.name == "Should fail for Invalid port number" {
				appConfig.HVSApiUrl = hvsApiUrl
				appConfig.Server.Port = 100
			} else if tt.name == "Validation should be successful" {
				appConfig.Server.Port = 7600
			}

			if err := uc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
