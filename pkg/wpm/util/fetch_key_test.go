/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	kbsc "github.com/intel-secl/intel-secl/v5/pkg/clients/kbs"
	"github.com/intel-secl/intel-secl/v5/pkg/wpm/config"
	testutil "github.com/intel-secl/intel-secl/v5/pkg/wpm/util/test"
	"gopkg.in/yaml.v3"
)

const (
	wpmTestDir          = "../../../test/wpm/"
	testImageFile       = wpmTestDir + "imagefile.txt"
	testPublicKey       = wpmTestDir + "publickey.pub"
	testPrivateKey      = wpmTestDir + "privatekey.pem"
	testEmptyPublicKey  = wpmTestDir + "emptyPublicKey.pem"
	testEmptyPrivateKey = wpmTestDir + "emptyPrivateKey.pem"
	testConfig          = wpmTestDir + "config.yml"
	trustedCAPath       = wpmTestDir
)

func TestFetchKey(t *testing.T) {

	err := testutil.CreateRSAKeyPair()
	if err != nil {
		t.Errorf("FetchKey() Failed to create test KeyPair %v", err)
		return
	}
	// Create testEmptyPublicKey
	var publicKeyInPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: nil,
	}

	publicKeyFile, err := os.OpenFile(testEmptyPublicKey, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "I/O error while encoding public envelope key file")
	}
	defer func() {
		derr := publicKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()

	err = pem.Encode(publicKeyFile, publicKeyInPem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while encoding the public envelope key")
	}

	defer func() {
		os.Remove(testPublicKey)
		os.Remove(testPrivateKey)
		os.Remove(testEmptyPublicKey)
		os.Remove(testEmptyPrivateKey)
	}()

	// Read Config
	testCfg, err := os.ReadFile(testConfig)
	if err != nil {
		log.Fatalf("Failed to load test WPM config file %v", err)
	}
	var wpmConfig *config.Configuration
	yaml.Unmarshal(testCfg, &wpmConfig)

	kbsClient, err := testutil.NewMockKBSClient(wpmConfig, trustedCAPath)
	if err != nil {
		t.Errorf("FetchKey() Failed to create MockKBSClinet %v", err)
		return
	}

	type args struct {
		keyID                     string
		assetTag                  string
		KBSApiUrl                 string
		envelopePublickeyLocation string
		KBSClient                 kbsc.KBSClient
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid case",
			args: args{
				KBSApiUrl:                 wpmConfig.KBSApiUrl,
				assetTag:                  "test:tag",
				envelopePublickeyLocation: testPublicKey,
				KBSClient:                 kbsClient,
			},
			wantErr: false,
		},
		{
			name: "Invalid case with empty KBSClient",
			args: args{
				KBSApiUrl:                 wpmConfig.KBSApiUrl,
				assetTag:                  "test:tag",
				envelopePublickeyLocation: testPublicKey,
				KBSClient:                 nil,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with empty publickey",
			args: args{
				KBSApiUrl:                 wpmConfig.KBSApiUrl,
				assetTag:                  "test:tag",
				envelopePublickeyLocation: testEmptyPublicKey,
				KBSClient:                 kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with invalid length of WrappedKey",
			args: args{
				keyID:                     "5c2cc23f-4697-47fd-b0ef-10fee512e489",
				KBSApiUrl:                 wpmConfig.KBSApiUrl,
				assetTag:                  "test:tag",
				envelopePublickeyLocation: testPublicKey,
				KBSClient:                 kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid AssetTag",
			args: args{
				KBSApiUrl: wpmConfig.KBSApiUrl,
				assetTag:  "testtag",
				KBSClient: kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with KEYID to validate GETKEY",
			args: args{
				keyID:     "c491f5f0-70e3-47a2-81bb-09c451b69707",
				KBSApiUrl: wpmConfig.KBSApiUrl,
				assetTag:  "testtag",
				KBSClient: kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with empty KBS url",
			args: args{
				KBSApiUrl: "",
				KBSClient: kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid KeyID",
			args: args{
				keyID:     "c491f5f0-70e3-47a2-81bb-09c451b69707%+o",
				KBSApiUrl: wpmConfig.KBSApiUrl,
				KBSClient: kbsClient,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err = FetchKey(tt.args.keyID, tt.args.assetTag, tt.args.KBSApiUrl, tt.args.envelopePublickeyLocation, tt.args.KBSClient)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewKBSClient(t *testing.T) {
	// Read Config
	testCfg, err := os.ReadFile(testConfig)
	if err != nil {
		log.Fatalf("Failed to load test WPM config file %v", err)
	}
	var wpmConfig *config.Configuration
	yaml.Unmarshal(testCfg, &wpmConfig)
	type args struct {
		config        *config.Configuration
		trustedCAPath string
	}
	tests := []struct {
		name    string
		args    args
		want    kbsc.KBSClient
		wantErr bool
	}{
		{
			name: "Invalid case with invalid AASURL",
			args: args{
				config: &config.Configuration{
					AASApiUrl: "https://127.0.0.1:8444/aas/v1/%+o/",
				},
				trustedCAPath: trustedCAPath,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with invalid KBSURL",
			args: args{
				config: &config.Configuration{
					AASApiUrl: "https://127.0.0.1:8444/aas/v1",
					KBSApiUrl: "https://127.0.0.1:8444/kbs/v1%+o",
				},
				trustedCAPath: trustedCAPath,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with NIL configuration",
			args: args{
				config:        nil,
				trustedCAPath: trustedCAPath,
			},
			wantErr: true,
		},
		{
			name: "Invalid CA Certificate",
			args: args{
				config:        wpmConfig,
				trustedCAPath: "../../../test/wpm/test.pem",
			},
			wantErr: true,
		},
		{
			name: "Valid case",
			args: args{
				config:        wpmConfig,
				trustedCAPath: trustedCAPath,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKBSClient(tt.args.config, tt.args.trustedCAPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKBSClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
