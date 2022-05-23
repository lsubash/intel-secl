/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	testutil "github.com/intel-secl/intel-secl/v5/pkg/wpm/util/test"
)

func TestUnwrapKey(t *testing.T) {
	err := testutil.CreateRSAKeyPair()
	if err != nil {
		t.Errorf("FetchKey() Failed to create test KeyPair %v", err)
		return
	}

	publicKeyFile, err := ioutil.ReadFile(testPublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Loading PublicKey file")
		return
	}
	pubKeyBytes, _ := pem.Decode(publicKeyFile)
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing PublicKey")
		return
	}

	publicKey := pubKey.(*rsa.PublicKey)

	var WrappedKey []byte
	key := []byte("7w!z%C*F)J@NcRfU")

	WrappedKey, err = rsa.EncryptOAEP(sha512.New384(), rand.Reader, publicKey, key, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
	}

	// Empty PrivateKey file
	emptyPrivateKeyFile, err := os.OpenFile(testEmptyPrivateKey, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "I/O error while saving private key file")
	}
	defer func() {
		derr := emptyPrivateKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()

	emptyprivateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: nil,
	}
	err = pem.Encode(emptyPrivateKeyFile, emptyprivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "I/O error while encoding private key file")
	}

	type args struct {
		wrappedKey         []byte
		privateKeyLocation string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Invalid Case with empty privateKey",
			args: args{
				privateKeyLocation: testEmptyPrivateKey,
				wrappedKey:         WrappedKey,
			},
			wantErr: true,
		},
		{
			name: "Invalid Case with empty privateKey location",
			args: args{
				privateKeyLocation: "",
				wrappedKey:         WrappedKey,
			},
			wantErr: true,
		},
		{
			name: "Invalid Case with Invalid privateKey location",
			args: args{
				privateKeyLocation: testPrivateKey,
				wrappedKey:         WrappedKey,
			},
			wantErr: false,
		},
		{
			name: "Invalid Case with empty WrappedKey location",
			args: args{
				privateKeyLocation: testPrivateKey,
				wrappedKey:         nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnwrapKey(tt.args.wrappedKey, tt.args.privateKeyLocation)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnwrapKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
