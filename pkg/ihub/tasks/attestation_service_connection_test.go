/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v5/pkg/ihub/test"
	"github.com/spf13/viper"
)

func TestAttestationServiceConnectionRun(t *testing.T) {
	server := testutility.MockServer(t)
	defer server.Close()

	time.Sleep(1 * time.Second)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	tests := []struct {
		name               string
		attestationService AttestationServiceConnection
		EnvValues          map[string]string
		wantErr            bool
	}{

		{
			name: "test-attestation-service-connection valid test 1",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_SERVICE_HVS_BASE_URL": server.URL + "/hvs/v2/",
			},

			wantErr: false,
		},

		{
			name: "test-attestation-service-connection negative test 1",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_SERVICE_HVS_BASE_URL": "",
			},

			wantErr: true,
		},

		{
			name: "test-attestation-service-connection negative test 2",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{},

			wantErr: true,
		},

		{
			name: "test-attestation-service-connection negative test 3",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_SERVICE_HVS_BASE_URL": server.URL + "hvs/v2",
			},

			wantErr: true,
		},

		{
			name: "test-attestation-service-connection negative test 4",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     os.Stdout,
			},
			EnvValues: map[string]string{
				"ATTESTATION_SERVICE_SHVS_BASE_URL": server.URL + "shvs/v1",
			},

			wantErr: true,
		},
	}
	for _, tt := range tests {
		for key := range tt.EnvValues {
			t.Run(tt.name, func(t *testing.T) {
				os.Unsetenv(key)
				os.Setenv(key, tt.EnvValues[key])
				defer func() {
					derr := os.Unsetenv(key)
					if derr != nil {
						t.Errorf("Error unseting ENV :%v", derr)
					}
				}()

				if err := tt.attestationService.Run(); (err != nil) != tt.wantErr {
					t.Errorf("tasks/attestation_service_connection_test:TestAttestationServiceConnectionRun() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		}
	}
}

func TestAttestationServiceConnectionValidate(t *testing.T) {

	server := testutility.MockServer(t)
	defer server.Close()

	time.Sleep(1 * time.Second)

	tests := []struct {
		name               string
		attestationService AttestationServiceConnection
		wantErr            bool
	}{

		{
			name: "attestation-service-connection-validate valid test1",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					HVSBaseURL: server.URL + "/hvs/v2/",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: false,
		},
		{
			name: "attestation-service-connection-validate negative test 1",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					HVSBaseURL: "",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
		{
			name: "attestation-service-connection-validate negative test 2",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					SHVSBaseURL: "",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
		{
			name: "attestation-service-connection-validate negative test 3",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					HVSBaseURL: server.URL + "hvs/v2",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
		{
			name: "test-attestation-service-connection negative test 4",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					SHVSBaseURL: server.URL + "shvs/v1",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
		{
			name: "attestation-service-connection-validate negative test5",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					HVSBaseURL: server.URL + "/hvs/v1/",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
		{
			name: "test-attestation-service-connection negative test 6",
			attestationService: AttestationServiceConnection{
				AttestationConfig: &config.AttestationConfig{
					SHVSBaseURL: server.URL + "/shvs/v2/",
				},
				ConsoleWriter: os.Stdout,
			},

			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if err := tt.attestationService.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("tasks/attestation_service_connection_test:TestAttestationServiceConnectionValidate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAttestationServiceConnection_PrintHelp(t *testing.T) {
	type fields struct {
		AttestationConfig *config.AttestationConfig
		ConsoleWriter     io.Writer
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name: "test-attestation-service-connection-printhelp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestationService := AttestationServiceConnection{
				AttestationConfig: tt.fields.AttestationConfig,
				ConsoleWriter:     tt.fields.ConsoleWriter,
			}
			w := &bytes.Buffer{}
			attestationService.PrintHelp(w)
		})
	}
}

func TestAttestationServiceConnection_SetName(t *testing.T) {
	type fields struct {
		AttestationConfig *config.AttestationConfig
		ConsoleWriter     io.Writer
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
			name: "test-attestation-service-connection-setname",
			fields: fields{
				AttestationConfig: &config.AttestationConfig{},
				ConsoleWriter:     nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestationService := AttestationServiceConnection{
				AttestationConfig: tt.fields.AttestationConfig,
				ConsoleWriter:     tt.fields.ConsoleWriter,
			}
			attestationService.SetName(tt.args.n, tt.args.e)
		})
	}
}
