/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
)

func TestDownloadSamlCaCertPrintHelp(t *testing.T) {
	type fields struct {
		HvsApiUrl         string
		ConsoleWriter     io.Writer
		SamlCertPath      string
		TrustedCaCertsDir string
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
			dc := DownloadSamlCaCert{
				HvsApiUrl:         tt.fields.HvsApiUrl,
				ConsoleWriter:     tt.fields.ConsoleWriter,
				SamlCertPath:      tt.fields.SamlCertPath,
				TrustedCaCertsDir: tt.fields.TrustedCaCertsDir,
			}
			w := &bytes.Buffer{}
			dc.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestDownloadSamlCaCertSetName(t *testing.T) {
	type fields struct {
		HvsApiUrl         string
		ConsoleWriter     io.Writer
		SamlCertPath      string
		TrustedCaCertsDir string
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
			dc := DownloadSamlCaCert{
				HvsApiUrl:         tt.fields.HvsApiUrl,
				ConsoleWriter:     tt.fields.ConsoleWriter,
				SamlCertPath:      tt.fields.SamlCertPath,
				TrustedCaCertsDir: tt.fields.TrustedCaCertsDir,
			}
			dc.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestDownloadSamlCaCertRun(t *testing.T) {

	server := mockServer(t)
	defer server.Close()
	var f *os.File
	var err error

	type fields struct {
		HvsApiUrl         string
		ConsoleWriter     io.Writer
		SamlCertPath      string
		TrustedCaCertsDir string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Should fail for empty Hvs URL",
			fields: fields{
				HvsApiUrl:     "",
				ConsoleWriter: &bytes.Buffer{},
			},
			wantErr: false,
		},
		{
			name: "Should fail for invalid Hvs URL",
			fields: fields{
				HvsApiUrl:     "http://localhost:443/@%*$$",
				ConsoleWriter: &bytes.Buffer{},
			},
			wantErr: true,
		},
		{
			name: "Should fail in writing response to file",
			fields: fields{
				HvsApiUrl:     server.URL + "/vs/v2/",
				ConsoleWriter: &bytes.Buffer{},
			},
			wantErr: true,
		},
		{
			name: "Should fail for retreiving ca cert for invalid url",
			fields: fields{
				HvsApiUrl:     server.URL + "/vs/v2/invalidurl",
				ConsoleWriter: &bytes.Buffer{},
			},
			wantErr: true,
		},
		{
			name: "Should download saml cert",
			fields: fields{
				HvsApiUrl:     server.URL + "/vs/v2/",
				ConsoleWriter: &bytes.Buffer{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := DownloadSamlCaCert{
				HvsApiUrl:         tt.fields.HvsApiUrl,
				ConsoleWriter:     tt.fields.ConsoleWriter,
				SamlCertPath:      tt.fields.SamlCertPath,
				TrustedCaCertsDir: tt.fields.TrustedCaCertsDir,
			}
			if tt.name == "Should download saml cert" {
				constants.SamlCaCertFilePath = "../samplesaml.pem"
				f, err = os.Create(constants.SamlCaCertFilePath)
				if err != nil {
					log.Fatal(err)
				}
			}

			if err := dc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadSamlCaCert.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if f != nil {
				f.Close()
			}
		})
	}
	err = os.Remove(constants.SamlCaCertFilePath)
	if err != nil {
		log.Fatal(err)
	}
}

var SampleSamlCertPath = "../mockJWTDir/jwtVerifier.pem"

func mockServer(t *testing.T) *httptest.Server {
	router := mux.NewRouter()

	router.HandleFunc("/vs/v2/ca-certificates", func(w http.ResponseWriter, router *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		samlReport, err := ioutil.ReadFile(SampleSamlCertPath)
		if err != nil {
			t.Log("wls/tasks:mockServer(): Unable to read file", err)
		}
		w.Write(samlReport)
	}).Methods(http.MethodGet)

	return httptest.NewServer(router)

}

func TestDownloadSamlCaCertValidate(t *testing.T) {

	var f *os.File
	var err error

	constants.SamlCaCertFilePath = "../samplesaml2.pem"

	type fields struct {
		HvsApiUrl         string
		ConsoleWriter     io.Writer
		SamlCertPath      string
		TrustedCaCertsDir string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name:    "Should fail for unable to open a file",
			fields:  fields{},
			wantErr: true,
		},
		{
			name:    "Validation should be successful",
			fields:  fields{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := DownloadSamlCaCert{
				HvsApiUrl:         tt.fields.HvsApiUrl,
				ConsoleWriter:     tt.fields.ConsoleWriter,
				SamlCertPath:      tt.fields.SamlCertPath,
				TrustedCaCertsDir: tt.fields.TrustedCaCertsDir,
			}

			if tt.name == "Validation should be successful" {
				f, err = os.Create(constants.SamlCaCertFilePath)
				if err != nil {
					log.Fatal(err)
				}
			}

			if err := dc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadSamlCaCert.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if f != nil {
				f.Close()
			}

		})
	}
	err = os.Remove(constants.SamlCaCertFilePath)
	if err != nil {
		log.Fatal(err)
	}
}
