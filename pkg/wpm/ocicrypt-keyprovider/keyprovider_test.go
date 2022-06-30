/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ocicrypt_keyprovider

import (
	"io/ioutil"
	"os"
	"testing"

	clients "github.com/intel-secl/intel-secl/v5/pkg/clients/kbs"
	kbsc "github.com/intel-secl/intel-secl/v5/pkg/clients/kbs"
	cnfg "github.com/intel-secl/intel-secl/v5/pkg/wpm/config"
	mocks "github.com/intel-secl/intel-secl/v5/pkg/wpm/util/mocks"
	testutil "github.com/intel-secl/intel-secl/v5/pkg/wpm/util/test"
	"gopkg.in/yaml.v3"
)

const (
	wpmTestDir                                          = "../../../test/wpm/"
	testConfig                                          = wpmTestDir + "config.yml"
	trustedCAPath                                       = wpmTestDir
	testPublicKey                                       = wpmTestDir + "publickey.pub"
	testPrivateKey                                      = wpmTestDir + "privatekey.pem"
	testKeyProviderKeyWrapProtocolInput                 = wpmTestDir + "testfiles/testinput_keywrap"
	testKeyProviderKeyWrapProtocolInputKeyID            = wpmTestDir + "testfiles/testinput_keywrapKeyID"
	testKeyProviderKeyWrapProtocolInputKeyID1           = wpmTestDir + "testfiles/testinput_keywrapKeyID1"
	testKeyProviderKeyWrapProtocolInputKeyIDWithNoIndex = wpmTestDir + "testfiles/testinput_keywrapKeyIDWithNoIndex"
	testKeyProviderKeyWrapProtocolIvalidOperation       = wpmTestDir + "testfiles/testinput_keywrapInvalidOperation"
	testKeyProviderKeyWrapProtocolInputInvalid          = wpmTestDir + "testfiles/testinput_keywrapInvalid"
	testKeyProviderKeyWrapProtocolInput_keyunwrap       = wpmTestDir + "testfiles/testinput_keyunwrap"
	testKeyProviderKeyWrapProtocolInput_invalid         = wpmTestDir + "testfiles/testinput_invalid"
)

var (
	testinput_keywrap                 = `{"op":"keywrap","keywrapparams":{"ec":{"Parameters":{"isecl":["YXNzZXQtdGFnOnZhbHVlMTIz"],"keyprovider-1":null},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`
	testinput_keywrapKeyID            = `{"op":"keywrap","keywrapparams":{"ec":{"Parameters":{"isecl":["a2V5LWlkOmYzOGMyYmFmLWEwMmYtNDExMC1iZGVhLTI5ZTA3NjExMzAxMw=="]},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`
	testinput_keywrapKeyID1           = `{"op":"keywrap","keywrapparams":{"ec":{"Parameters":{"isecl":["a2V5LWlkOjAzODMwNjMzLTUwMGYtNDM4YS1iZjMxLWQ4N2U1NGRhMWFmOQ=="]},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`
	testinput_keywrapKeyIDWithNoIndex = `{"op":"keywrap","keywrapparams":{"ec":{"Parameters":{"isecl":["a2V5LWlk"]},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`
	testinput_keywrapInvalidOperation = `{"op":"keywrap","keywrapparams":{"ec":{"Parameters":{"invalid":["aW52YWxpZDoxMjM="]},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`
	testinput_keywrapInvalid          = `{"op":"keywrap","keywrapparams":{"ec":{"Parameters":{"isecl":["aW52YWxpZDoxMjM="]},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`
	testinput_keyunwrap               = `{"op":"keyunwrap","keywrapparams":{"ec":{"Parameters":{"isecl":["YXNzZXQtdGFnOnZhbHVlMTIz"],"keyprovider-1":null},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`
	testinput_invalid                 = `{"op":"invalid","keywrapparams":{"ec":{"Parameters":{"isecl":["YXNzZXQtdGFnOnZhbHVlMTIz"],"keyprovider-1":null},"DecryptConfig":{"Parameters":null}},"optsdata":"ZGF0YSB0byBiZSBlbmNyeXB0ZWQ="},"keyunwrapparams":{"dc":null,"annotation":null}}`

	testFileMap map[string]string
	wpmConfig   *cnfg.Configuration
)

func createTestFiles() {

	testFileMap = make(map[string]string)

	testFileMap[testKeyProviderKeyWrapProtocolInput] = testinput_keywrap
	testFileMap[testKeyProviderKeyWrapProtocolInputKeyID] = testinput_keywrapKeyID
	testFileMap[testKeyProviderKeyWrapProtocolInputKeyID1] = testinput_keywrapKeyID1
	testFileMap[testKeyProviderKeyWrapProtocolInputKeyIDWithNoIndex] = testinput_keywrapKeyIDWithNoIndex
	testFileMap[testKeyProviderKeyWrapProtocolIvalidOperation] = testinput_keywrapInvalidOperation
	testFileMap[testKeyProviderKeyWrapProtocolInputInvalid] = testinput_keywrapInvalid
	testFileMap[testKeyProviderKeyWrapProtocolInput_keyunwrap] = testinput_keyunwrap
	testFileMap[testKeyProviderKeyWrapProtocolInput_invalid] = testinput_invalid

	for fileName, fileContent := range testFileMap {
		err := ioutil.WriteFile(fileName, []byte(fileContent), 0640)
		if err != nil {
			log.Fatalf("failed to create test file %s with error %v", fileName, err)
		}
	}
}

func removeTestFiles() {
	for fileName, _ := range testFileMap {
		err := os.Remove(fileName)
		if err != nil {
			log.Fatalf("failed to remove test file %s with error %v", fileName, err)
		}
	}
}

func TestAESEncrypt(t *testing.T) {
	type args struct {
		kek    []byte
		symKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid case with valid kek and symKey",
			args: args{
				kek:    []byte("TZPtSIacEJG18IpqQSkTE6luYmnCNKgR"),
				symKey: []byte("TZPtSIacEJG18IpqQSkTE6luYmnCNKgR"),
			},
			wantErr: false,
		},
		{
			name: "Invalid case with nil kek",
			args: args{
				kek:    nil,
				symKey: []byte("TZPtSIacEJG18IpqQSkTE6luYmnCNKgR"),
			},
			wantErr: true,
		},
		{
			name: "Invalid case with nil symKey",
			args: args{
				kek:    []byte("TZPtSIacEJG18IpqQSkTE6luYmnCNKgR"),
				symKey: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := aesEncrypt(tt.args.kek, tt.args.symKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("aesEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGetKey(t *testing.T) {

	createTestFiles()
	defer removeTestFiles()

	// Read Config
	testCfg, _ := os.ReadFile(testConfig)
	yaml.Unmarshal(testCfg, &wpmConfig)

	err := testutil.CreateRSAKeyPair()
	if err != nil {
		t.Errorf("FetchKey() Failed to create test KeyPair %v", err)
		return
	}
	defer func() {
		os.Remove(testPublicKey)
		os.Remove(testPrivateKey)
	}()

	kbsClient := clients.NewMockKBSClient()

	type args struct {
		FileName                   string
		OcicryptKeyProviderName    string
		KBSApiUrl                  string
		envelopePrivatekeyLocation string
		envelopePublickeyLocation  string
		KBSClient                  kbsc.KBSClient
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid Case with KeyWrap-AssetTag",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInput,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: testPrivateKey,
				envelopePublickeyLocation:  testPublicKey,
				KBSClient:                  kbsClient,
			},
			wantErr: false,
		},
		{
			name: "Valid Case with KeyWrap-KeyID",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInputKeyID,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: testPrivateKey,
				envelopePublickeyLocation:  testPublicKey,
				KBSClient:                  kbsClient,
			},
			wantErr: false,
		},
		{
			name: "Valid Case with KeyWrap-configFileInvalid",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInputInvalid,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: testPrivateKey,
				envelopePublickeyLocation:  testPublicKey,
				KBSClient:                  kbsClient,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mocks.MockCreateKey(tt.args.KBSApiUrl, tt.args.KBSClient.(*kbsc.MockKbsClient))
			mocks.MockGetKey("f38c2baf-a02f-4110-bdea-29e076113013", tt.args.KBSClient.(*kbsc.MockKbsClient))
			testFile, err := os.OpenFile(tt.args.FileName, os.O_RDONLY, 640)
			if err != nil {
				t.Errorf("GetKey() Failed to open file = %s, withErr %v", tt.args.FileName, err)
				return
			}
			defer testFile.Close()
			keyProvider := NewKeyProvider(testFile, tt.args.OcicryptKeyProviderName, tt.args.KBSApiUrl,
				tt.args.envelopePublickeyLocation, tt.args.envelopePrivatekeyLocation, tt.args.KBSClient.(*kbsc.MockKbsClient))
			if err := keyProvider.GetKey(); (err != nil) != tt.wantErr {
				t.Errorf("GetKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Negative Cases
func TestGetKeyNegativeCases(t *testing.T) {

	createTestFiles()
	defer removeTestFiles()
	// Read Config
	testCfg, _ := os.ReadFile(testConfig)
	yaml.Unmarshal(testCfg, &wpmConfig)

	err := testutil.CreateRSAKeyPair()
	if err != nil {
		t.Errorf("FetchKey() Failed to create test KeyPair %v", err)
		return
	}
	defer func() {
		os.Remove(testPublicKey)
		os.Remove(testPrivateKey)
	}()

	kbsClient := clients.NewMockKBSClient()

	type args struct {
		FileName                   string
		OcicryptKeyProviderName    string
		KBSApiUrl                  string
		envelopePrivatekeyLocation string
		envelopePublickeyLocation  string
		KBSClient                  kbsc.KBSClient
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Invalid Case with empty publickey location for KeyWrap-KeyID",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInputKeyID,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: testPrivateKey,
				envelopePublickeyLocation:  "",
				KBSClient:                  kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid Case with empty publickey location for KeyWrap-configFileInvalid ",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInputInvalid,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: testPrivateKey,
				envelopePublickeyLocation:  "",
				KBSClient:                  kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid Case with KeyWrap-AssetTag with empty envelopePublickeyLocation",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInput,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: testPrivateKey,
				envelopePublickeyLocation:  "",
				KBSClient:                  kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with Operation keyunwrap",
			args: args{
				FileName:                testKeyProviderKeyWrapProtocolInput_keyunwrap,
				OcicryptKeyProviderName: "isecl",
				KBSApiUrl:               "https://127.0.0.1:9443/kbs/v1/",
				KBSClient:               kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with Operation Invalid",
			args: args{
				FileName:                testKeyProviderKeyWrapProtocolInput_invalid,
				OcicryptKeyProviderName: "isecl",
				KBSApiUrl:               "https://127.0.0.1:9443/kbs/v1/",
				KBSClient:               kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with Operation keywrap with invalid protocol",
			args: args{
				FileName:                testKeyProviderKeyWrapProtocolIvalidOperation,
				OcicryptKeyProviderName: "isecl",
				KBSApiUrl:               "https://127.0.0.1:9443/kbs/v1/",
				KBSClient:               kbsClient,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.KBSClient != nil {
				mocks.MockCreateKey(tt.args.KBSApiUrl, tt.args.KBSClient.(*kbsc.MockKbsClient))
				mocks.MockGetKey("f38c2baf-a02f-4110-bdea-29e076113013", tt.args.KBSClient.(*kbsc.MockKbsClient))
			}
			testFile, err := os.OpenFile(tt.args.FileName, os.O_RDONLY, 640)
			if err != nil {
				t.Errorf("GetKey() Failed to open file = %s, withErr %v", tt.args.FileName, err)
				return
			}
			defer testFile.Close()
			keyProvider := NewKeyProvider(testFile, tt.args.OcicryptKeyProviderName, tt.args.KBSApiUrl,
				tt.args.envelopePublickeyLocation, tt.args.envelopePrivatekeyLocation, tt.args.KBSClient.(*kbsc.MockKbsClient))
			if err := keyProvider.GetKey(); (err != nil) != tt.wantErr {
				t.Errorf("GetKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Negative Cases
func TestGetKeyNegativeCasesEmptyPritvateKey(t *testing.T) {
	createTestFiles()
	defer removeTestFiles()
	// Read Config
	testCfg, _ := os.ReadFile(testConfig)
	yaml.Unmarshal(testCfg, &wpmConfig)

	err := testutil.CreateRSAKeyPair()
	if err != nil {
		t.Errorf("FetchKey() Failed to create test KeyPair %v", err)
		return
	}
	defer func() {
		os.Remove(testPublicKey)
		os.Remove(testPrivateKey)
	}()

	kbsClient := clients.NewMockKBSClient()

	type args struct {
		FileName                   string
		OcicryptKeyProviderName    string
		KBSApiUrl                  string
		envelopePrivatekeyLocation string
		envelopePublickeyLocation  string
		KBSClient                  kbsc.KBSClient
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Invalid Case with empty private key location KeyWrap-KeyID",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInputKeyID,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: "",
				envelopePublickeyLocation:  testPublicKey,
				KBSClient:                  kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid Case with empty private key location KeyWrap-configFileInvalid",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInputInvalid,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: "",
				envelopePublickeyLocation:  testPublicKey,
				KBSClient:                  kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid Case with empty PrivateKey location - KeyWrap-AssetTag",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInput,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: "",
				envelopePublickeyLocation:  testPublicKey,
				KBSClient:                  kbsClient,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with empty private key location - Encryption criteria not provided",
			args: args{
				FileName:                   testKeyProviderKeyWrapProtocolInputKeyIDWithNoIndex,
				OcicryptKeyProviderName:    "isecl",
				KBSApiUrl:                  "https://127.0.0.1:9443/kbs/v1/",
				envelopePrivatekeyLocation: "",
				envelopePublickeyLocation:  testPublicKey,
				KBSClient:                  kbsClient,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mocks.MockCreateKey(tt.args.KBSApiUrl, tt.args.KBSClient.(*kbsc.MockKbsClient))
			mocks.MockGetKey("f38c2baf-a02f-4110-bdea-29e076113013", tt.args.KBSClient.(*kbsc.MockKbsClient))
			testFile, err := os.OpenFile(tt.args.FileName, os.O_RDONLY, 640)
			if err != nil {
				t.Errorf("GetKey() Failed to open file = %s, withErr %v", tt.args.FileName, err)
				return
			}
			defer testFile.Close()
			keyProvider := NewKeyProvider(testFile, tt.args.OcicryptKeyProviderName, tt.args.KBSApiUrl,
				tt.args.envelopePublickeyLocation, tt.args.envelopePrivatekeyLocation, tt.args.KBSClient.(*kbsc.MockKbsClient))
			if err := keyProvider.GetKey(); (err != nil) != tt.wantErr {
				t.Errorf("GetKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
