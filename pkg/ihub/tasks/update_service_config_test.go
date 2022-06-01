/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"io"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/constants"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
)

func TestUpdateServiceConfig_Run(t *testing.T) {

	sc := &config.Configuration{
		IHUB: commConfig.ServiceConfig{},
	}

	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test-updateserviceconfig-run valid case 1",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "ihubUser",
					Password: "ihubPass",
				},
				AASApiUrl: "http://localhost",
				AppConfig: &sc,
			},
			wantErr: false,
		},
		{
			name: "test-updateserviceconfig-run negative case 1",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "",
					Password: "ihubPass",
				},
				AASApiUrl: "http://localhost",
				AppConfig: &sc,
			},
			wantErr: true,
		},
		{
			name: "test-updateserviceconfig-run negative case 2",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "ihubUser",
					Password: "",
				},
				AASApiUrl: "http://localhost",
				AppConfig: &sc,
			},
			wantErr: true,
		},
		{
			name: "test-updateserviceconfig-run negative case 3",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "ihubUser",
					Password: "ihubPass",
				},
				AASApiUrl: "",
				AppConfig: &sc,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			if err := uc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfig_Validate(t *testing.T) {

	case1 := &config.Configuration{
		IHUB: commConfig.ServiceConfig{
			Username: "",
			Password: "",
		},
		Log: commConfig.LogConfig{
			MaxLength:    constants.DefaultLogEntryMaxlength,
			Level:        constants.DefaultLogLevel,
			EnableStdout: true,
		},
	}

	case2 := &config.Configuration{
		IHUB: commConfig.ServiceConfig{
			Username: "ihubUser",
			Password: "",
		},
		Log: commConfig.LogConfig{
			MaxLength:    constants.DefaultLogEntryMaxlength,
			Level:        constants.DefaultLogLevel,
			EnableStdout: true,
		},
	}

	case3 := &config.Configuration{
		IHUB: commConfig.ServiceConfig{
			Username: "ihubUser",
			Password: "ihubPass",
		},
		Log: commConfig.LogConfig{
			MaxLength:    constants.DefaultLogEntryMaxlength,
			Level:        constants.DefaultLogLevel,
			EnableStdout: true,
		},
	}

	case4 := &config.Configuration{
		IHUB: commConfig.ServiceConfig{
			Username: "ihubUser",
			Password: "ihubPass",
		},
		Log: commConfig.LogConfig{
			MaxLength:    10,
			Level:        constants.DefaultLogLevel,
			EnableStdout: true,
		},
	}

	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test-updateserviceconfig-validate case 1",
			fields: fields{
				AppConfig: &case1,
			},
			wantErr: true,
		},
		{
			name: "test-updateserviceconfig-validate case 2",
			fields: fields{
				AppConfig: &case2,
			},
			wantErr: true,
		},
		{
			name: "test-updateserviceconfig-validate case 3",
			fields: fields{
				AppConfig: &case3,
			},
			wantErr: false,
		},
		{
			name: "test-updateserviceconfig-validate case 4",
			fields: fields{
				AppConfig: &case4,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			if err := uc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfig_PrintHelp(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name: "test_updateserviceconfig_printhelp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			w := &bytes.Buffer{}
			uc.PrintHelp(w)
		})
	}
}
