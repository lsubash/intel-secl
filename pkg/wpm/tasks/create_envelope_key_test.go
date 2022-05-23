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
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	wpmTestDir         = "../../../test/wpm/"
	testPublicKey      = wpmTestDir + "publickey.pub"
	testPrivateKey     = wpmTestDir + "privatekey.pem"
	testPublicKey_new  = wpmTestDir + "publickey_new.pub"
	testPrivateKey_new = wpmTestDir + "privatekey_new.pem"
)

func TestCreateEnvelopeKey_Validate(t *testing.T) {
	defer func() {
		os.Remove(testPrivateKey)
		os.Remove(testPublicKey)
	}()

	// Create RSA key pair
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while generating new RSA key pair")
	}

	// save private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	privateKeyFile, err := os.OpenFile(testPrivateKey, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "I/O error while saving private key file")
	}
	defer func() {
		derr := privateKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(privateKeyFile, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "I/O error while encoding private key file")
	}

	// save public key
	publicKey := &keyPair.PublicKey

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "I/O error while encoding private key file")
	}
	var publicKeyInPem = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyBytes,
	}

	publicKeyFile, err := os.OpenFile(testPublicKey, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
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

	type fields struct {
		EnvelopePrivatekeyLocation string
		EnvelopePublickeyLocation  string
		KeyAlgorithmLength         int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Invalid case with Invalid EnvelopePrivatekeyLocation",
			fields: fields{
				EnvelopePrivatekeyLocation: "",
			},
			wantErr: true,
		},
		{
			name: "Invalid case with Invalid EnvelopePublickeyLocation",
			fields: fields{
				EnvelopePrivatekeyLocation: testPrivateKey,
				EnvelopePublickeyLocation:  "",
			},
			wantErr: true,
		},
		{
			name: "Valid case with Valid KeyPairLocaiton",
			fields: fields{
				EnvelopePrivatekeyLocation: testPrivateKey,
				EnvelopePublickeyLocation:  testPublicKey,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ek := CreateEnvelopeKey{
				EnvelopePrivatekeyLocation: tt.fields.EnvelopePrivatekeyLocation,
				EnvelopePublickeyLocation:  tt.fields.EnvelopePublickeyLocation,
				KeyAlgorithmLength:         tt.fields.KeyAlgorithmLength,
			}
			if err := ek.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CreateEnvelopeKey.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateEnvelopeKey_Run(t *testing.T) {
	defer func() {
		os.Remove(testPrivateKey_new)
		os.Remove(testPublicKey_new)
	}()
	type fields struct {
		EnvelopePrivatekeyLocation string
		EnvelopePublickeyLocation  string
		KeyAlgorithmLength         int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid case with Valid KeyPairlocation and KeyLenght",
			fields: fields{
				EnvelopePrivatekeyLocation: testPrivateKey_new,
				EnvelopePublickeyLocation:  testPublicKey_new,
				KeyAlgorithmLength:         2048,
			},
			wantErr: false,
		},
		{
			name: "Invalid case with Invalid private key location",
			fields: fields{
				EnvelopePrivatekeyLocation: "",
				EnvelopePublickeyLocation:  testPublicKey_new,
				KeyAlgorithmLength:         2048,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with Invalid public key location",
			fields: fields{
				EnvelopePrivatekeyLocation: testPrivateKey_new,
				EnvelopePublickeyLocation:  "",
				KeyAlgorithmLength:         2048,
			},
			wantErr: true,
		},
		{
			name: "Invalid case with Invalid keyLength",
			fields: fields{
				EnvelopePrivatekeyLocation: testPrivateKey_new,
				EnvelopePublickeyLocation:  "",
				KeyAlgorithmLength:         0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ek := CreateEnvelopeKey{
				EnvelopePrivatekeyLocation: tt.fields.EnvelopePrivatekeyLocation,
				EnvelopePublickeyLocation:  tt.fields.EnvelopePublickeyLocation,
				KeyAlgorithmLength:         tt.fields.KeyAlgorithmLength,
			}
			if err := ek.Run(); (err != nil) != tt.wantErr {
				t.Errorf("CreateEnvelopeKey.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPrintHelp_SetName(t *testing.T) {
	ek := CreateEnvelopeKey{}
	ek.PrintHelp(os.Stdout)
	assert.NoError(t, nil)

	ek.SetName("test", "test1")
	assert.NoError(t, nil)
}

func TestCreateEnvelopeKey_PrintHelp(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Valid case",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ek := CreateEnvelopeKey{}
			w := &bytes.Buffer{}
			ek.PrintHelp(w)
		})
	}
}
