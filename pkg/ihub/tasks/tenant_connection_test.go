/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v5/pkg/ihub/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	apiServerCert = "../test/resources/apiserver.crt"
)

func createAPIServerCertificate() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"K8S TEST, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	// save certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatalf("Failed to CreateCertificate %v", err)
	}
	caPEMFile, err := os.OpenFile(apiServerCert, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := caPEMFile.Close()
		if derr != nil {
			log.Fatalf("Error while closing file" + derr.Error())
		}
	}()
	err = pem.Encode(caPEMFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		log.Fatalf("Failed to Encode Certificate %v", err)
	}
	return
}

func TestTenantConnectionRun(t *testing.T) {
	server := testutility.MockServer(t)
	defer server.Close()

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	k8sConfig := testutility.SetupMockK8sConfiguration(t, server.URL)

	// Create test APIServerCertificate
	createAPIServerCertificate()
	defer func() {
		err := os.Remove(apiServerCert)
		assert.NoError(t, err)
	}()

	k8sConfig.Endpoint.CertFile = apiServerCert

	type args struct {
		EnvValues map[string]string
	}
	tests := []struct {
		name             string
		tenantConnection TenantConnection
		args             args
		wantErr          bool
	}{
		{
			name: "tenant-connection-kubernetes valid test 1",
			tenantConnection: TenantConnection{
				TenantConfig:  &config.Endpoint{},
				ConsoleWriter: os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       server.URL + "/",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: false,
		},
		{
			name: "tenant-connection-kubernetes negative test 1",
			tenantConnection: TenantConnection{
				TenantConfig:  &config.Endpoint{},
				ConsoleWriter: os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       "",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 2",
			tenantConnection: TenantConnection{
				TenantConfig:  &config.Endpoint{},
				ConsoleWriter: os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       server.URL + "/",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     "",
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 3",
			tenantConnection: TenantConnection{
				TenantConfig:  &config.Endpoint{},
				ConsoleWriter: os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               k8sConfig.Endpoint.Type,
					"KUBERNETES_URL":       server.URL + "/",
					"KUBERNETES_CRD":       "",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": "",
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 4",
			tenantConnection: TenantConnection{
				TenantConfig:  &config.Endpoint{},
				ConsoleWriter: os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"KUBERNETES_URL":       server.URL + "/",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
		{
			name: "tenant-connection-kubernetes negative test 5",
			tenantConnection: TenantConnection{
				TenantConfig:  &config.Endpoint{},
				ConsoleWriter: os.Stdout,
			},
			args: args{
				EnvValues: map[string]string{
					"TENANT":               "INVALID",
					"KUBERNETES_URL":       server.URL + "/",
					"KUBERNETES_CRD":       "custom-isecl",
					"KUBERNETES_TOKEN":     k8sConfig.Endpoint.Token,
					"KUBERNETES_CERT_FILE": k8sConfig.Endpoint.CertFile,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key := range tt.args.EnvValues {
				os.Setenv(key, tt.args.EnvValues[key])
				defer os.Unsetenv(key)
			}
			temp, err := ioutil.TempFile("", "config.yml")
			if err != nil {
				t.Log("tasks/tenant_connection_test:TestTenantConnectionRun(): Error in Reading Config File")
			}
			defer func() {
				cerr := temp.Close()
				if cerr != nil {
					t.Errorf("Error closing file: %v", cerr)
				}
				derr := os.Remove(temp.Name())
				if derr != nil {
					t.Errorf("Error removing file :%v", derr)
				}
			}()
			conf, _ := config.LoadConfiguration()
			tt.tenantConnection.TenantConfig = &conf.Endpoint
			tt.tenantConnection.K8SCertFile = apiServerCert
			err = tt.tenantConnection.Run()
			goterr := err != nil
			if goterr != tt.wantErr {
				t.Errorf("tasks/tenant_connection_test:TestTenantConnectionRun() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTenantConnectionValidate(t *testing.T) {
	server := testutility.MockServer(t)
	defer server.Close()

	var k8sConfig *config.Configuration
	k8sConfig = testutility.SetupMockK8sConfiguration(t, server.URL)

	t2 := TenantConnection{
		TenantConfig:  &k8sConfig.Endpoint,
		ConsoleWriter: os.Stdout,
	}
	tests := []struct {
		name             string
		tenantConnection TenantConnection
		wantErr          bool
	}{
		{
			name:             "tenant-connection-validate-service k8s valid test 2",
			tenantConnection: t2,
			wantErr:          false,
		},
		{
			name:             "tenant-connection-validate-service k8s negative test 1",
			tenantConnection: t2,
			wantErr:          true,
		},
		{
			name:             "tenant-connection-validate-service k8s negative test 2",
			tenantConnection: t2,
			wantErr:          true,
		},
		{
			name:             "tenant-connection-validate-service k8s negative test 3",
			tenantConnection: t2,
			wantErr:          true,
		},
		{
			name:             "tenant-connection-validate-service k8s negative test 4",
			tenantConnection: t2,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "tenant-connection-validate-service k8s negative test 1" {
				tt.tenantConnection.TenantConfig.URL = ""
			} else if tt.name == "tenant-connection-validate-service k8s negative test 2" {
				k8sConfig = testutility.SetupMockK8sConfiguration(t, server.URL)
				tt.tenantConnection.TenantConfig = &k8sConfig.Endpoint
				tt.tenantConnection.ConsoleWriter = os.Stdout
				tt.tenantConnection.TenantConfig.CRDName = ""
				tt.tenantConnection.TenantConfig.Token = ""
				tt.tenantConnection.TenantConfig.CertFile = ""
			} else if tt.name == "tenant-connection-validate-service k8s negative test 3" {
				k8sConfig = testutility.SetupMockK8sConfiguration(t, server.URL)
				tt.tenantConnection.TenantConfig = &k8sConfig.Endpoint
				tt.tenantConnection.ConsoleWriter = os.Stdout
				tt.tenantConnection.TenantConfig.URL = "127.0.0.1:\v1"
			} else if tt.name == "tenant-connection-validate-service k8s negative test 4" {
				k8sConfig = testutility.SetupMockK8sConfiguration(t, server.URL)
				tt.tenantConnection.TenantConfig = &k8sConfig.Endpoint
				tt.tenantConnection.ConsoleWriter = os.Stdout
				tt.tenantConnection.TenantConfig.Token = ""
			}
			if err := tt.tenantConnection.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("TenantConnection.validateService() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTenantConnection_PrintHelp(t *testing.T) {
	type fields struct {
		TenantConfig  *config.Endpoint
		ConsoleWriter io.Writer
		K8SCertFile   string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name: "test-tenantconnection-printhelp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantConnection := TenantConnection{
				TenantConfig:  tt.fields.TenantConfig,
				ConsoleWriter: tt.fields.ConsoleWriter,
				K8SCertFile:   tt.fields.K8SCertFile,
			}
			w := &bytes.Buffer{}
			tenantConnection.PrintHelp(w)
		})
	}
}
