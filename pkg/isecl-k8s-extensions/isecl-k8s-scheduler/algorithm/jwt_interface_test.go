/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package algorithm

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/Waterdrips/jwt-go"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

const (
	EnvelopePublickeyLocation = "../../test_utility/envelopePublicKey.pem"
)

func TestParseRSAPublicKeyFromPEM(t *testing.T) {

	invalidPublicKey := `
	-----BEGIN PUBLIC KEY-----
	MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAo0cG2D2fGTgcmc3VXq4W
	IlosF+hIUUYa50+syZxSmrrMeba8fH6tDrQcmiffMc65V3wwi/ISIKXNCDVgU417
	KwMj4ScZz0Jr6RhWLJrdY8eYluC8mt7nWN1VB5gbaDT6T7lXC4Xwam3SJBYQvrfG
	zSAYnnyIHMxGuAMbZ3xg7tz2Jy0iW7tfT+bq2cjdNbjwHXOT4VvfEOdsF7BCKDi3
	MxTIgwuqldMr+9n6pWnHMtzMK5cYX8/paitLcOqASZyHjXiPn2nNK+U1VK17Jq9V
	6MzGFHmQrR/nSkohTyiNYW2/zqRuRMvjkpX6YmTAXLUIvH8siNQkGPZfWc7yLx/x
	xeW/cq6ej3A/aodvYSFEZlIXT0y27q8+jmPZiEIguC0iVF2gkdm+dyfTxji5FWuY
	fwhKWvRuOkM2kTEHgBz/HiieEV0UnuQpZHk9Ghp2L1zFrN3OoGQ+YXg0iATynnnz
	z5DWXTXyd5YMwAG+N5QZZPboTmx9lZ1i5F6eLuQ5pTnnAgMBAAE=
	-----END PUBLIC KEY-----`

	publicKey := `
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAo0cG2D2fGTgcmc3VXq4W
IlosF+hIUUYa50+syZxSmrrMeba8fH6tDrQcmiffMc65V3wwi/ISIKXNCDVgU417
KwMj4ScZz0Jr6RhWLJrdY8eYluC8mt7nWN1VB5gbaDT6T7lXC4Xwam3SJBYQvrfG
zSAYnnyIHMxGuAMbZ3xg7tz2Jy0iW7tfT+bq2cjdNbjwHXOT4VvfEOdsF7BCKDi3
MxTIgwuqldMr+9n6pWnHMtzMK5cYX8/paitLcOqASZyHjXiPn2nNK+U1VK17Jq9V
6MzGFHmQrR/nSkohTyiNYW2/zqRuRMvjkpX6YmTAXLUIvH8siNQkGPZfWc7yLx/x
xeW/cq6ej3A/aodvYSFEZlIXT0y27q8+jmPZiEIguC0iVF2gkdm+dyfTxji5FWuY
fwhKWvRuOkM2kTEHgBz/HiieEV0UnuQpZHk9Ghp2L1zFrN3OoGQ+YXg0iATynnnz
z5DWXTXyd5YMwAG+N5QZZPboTmx9lZ1i5F6eLuQ5pTnnAgMBAAE=
-----END PUBLIC KEY-----`

	type args struct {
		pubKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test 1",
			args: args{
				pubKey: []byte(publicKey),
			},
			wantErr: false,
		},
		{
			name: "Test 2",
			args: args{
				pubKey: []byte(invalidPublicKey),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRSAPublicKeyFromPEM(tt.args.pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRSAPublicKeyFromPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestValidateAnnotationByPublicKey(t *testing.T) {

	invalidPubKey := `
	-----BEGIN PUBLIC KEY-----
	MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAo0cG2D2fGTgcmc3VXq4W
	IlosF+hIUUYa50+syZxSmrrMeba8fH6tDrQcmiffMc65V3wwi/ISIKXNCDVgU417
	KwMj4ScZz0Jr6RhWLJrdY8eYluC8mt7nWN1VB5gbaDT6T7lXC4Xwam3SJBYQvrfG
	zSAYnnyIHMxGuAMbZ3xg7tz2Jy0iW7tfT+bq2cjdNbjwHXOT4VvfEOdsF7BCKDi3
	MxTIgwuqldMr+9n6pWnHMtzMK5cYX8/paitLcOqASZyHjXiPn2nNK+U1VK17Jq9V
	6MzGFHmQrR/nSkohTyiNYW2/zqRuRMvjkpX6YmTAXLUIvH8siNQkGPZfWc7yLx/x
	xeW/cq6ej3A/aodvYSFEZlIXT0y27q8+jmPZiEIguC0iVF2gkdm+dyfTxji5FWuY
	fwhKWvRuOkM2kTEHgBz/HiieEV0UnuQpZHk9Ghp2L1zFrN3OoGQ+YXg0iATynnnz
	z5DWXTXyd5YMwAG+N5QZZPboTmx9lZ1i5F6eLuQ5pTnnAgMBAAE=
	-----END PUBLIC KEY-----`

	pub3, _ := ioutil.ReadFile(EnvelopePublickeyLocation)

	signature := "test-signature"
	encodedSignature := base64.URLEncoding.EncodeToString([]byte(signature))

	jwtHeader := JwtHeader{
		KeyId:     "fgtQtItsm9uCvfuD5D1Popeq4xA=",
		Type:      encodedSignature,
		Algorithm: "SHA1",
	}

	j, err := json.Marshal(jwtHeader)
	if err != nil {
		assert.NoError(t, err)
	}
	encodedCipherText := base64.URLEncoding.EncodeToString(j)
	encodedCipherText = encodedCipherText + ".alg" + "." + encodedSignature

	jwtHeaderWithWrongKey := JwtHeader{
		KeyId:     "eKBghoN8kpOoybcMC9q9udd+7t8=",
		Type:      encodedSignature,
		Algorithm: "SHA1",
	}
	jk, err := json.Marshal(jwtHeaderWithWrongKey)
	if err != nil {
		assert.NoError(t, err)
	}
	encodedCipherTextWithWrongKey := base64.URLEncoding.EncodeToString(jk)
	encodedCipherTextWithWrongKey = encodedCipherTextWithWrongKey + ".alg" + "." + encodedSignature

	type args struct {
		cipherText string
		iHubPubKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test 1 final rsa verification failure",
			args: args{
				cipherText: encodedCipherText,
				iHubPubKey: pub3,
			},
			wantErr: true,
		},
		{
			name: "Test 2 invalid token",
			args: args{
				cipherText: "testsample2",
				iHubPubKey: pub3,
			},
			wantErr: true,
		},
		{
			name: "Test 3 Failed to unmarshal jwt header",
			args: args{
				cipherText: "test.sample.1",
				iHubPubKey: pub3,
			},
			wantErr: true,
		},
		{
			name: "Test 4 adding = and invalid token",
			args: args{
				cipherText: "testing.sample.1",
				iHubPubKey: pub3,
			},
			wantErr: true,
		},
		{
			name: "Test 5 failed to decode jwt header",
			args: args{
				cipherText: "@#!",
				iHubPubKey: pub3,
			},
			wantErr: true,
		},
		{
			name: "Test 6 invalid pub key",
			args: args{
				cipherText: encodedCipherText,
				iHubPubKey: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "Test 7 wrong key ID",
			args: args{
				cipherText: encodedCipherTextWithWrongKey,
				iHubPubKey: pub3,
			},
			wantErr: true,
		},
		{
			name: "Test 8 invalid pub key data",
			args: args{
				cipherText: encodedCipherText,
				iHubPubKey: []byte(invalidPubKey),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAnnotationByPublicKey(tt.args.cipherText, tt.args.iHubPubKey); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAnnotationByPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWTParseWithClaims(t *testing.T) {

	jwtTestDefaultKey, _ := ioutil.ReadFile(EnvelopePublickeyLocation)

	var defaultKeyFunc jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestDefaultKey, nil }

	var jwtTestData = struct {
		name        string
		tokenString string
		keyfunc     jwt.Keyfunc
		claims      jwt.Claims
		valid       bool
		errors      uint32
		parser      *jwt.Parser
	}{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		jwt.MapClaims{"foo": "bar"},
		true,
		0,
		nil,
	}

	type args struct {
		cipherText string
		claim      jwt.MapClaims
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test 1",
			args: args{
				cipherText: jwtTestData.tokenString,
				claim:      jwt.MapClaims{},
			},
			want: true,
		},
		{
			name: "Test 2 failure",
			args: args{
				cipherText: "testsample",
				claim:      jwt.MapClaims{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := JWTParseWithClaims(tt.args.cipherText, tt.args.claim); got != tt.want {
				t.Errorf("JWTParseWithClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckAnnotationAttrib(t *testing.T) {

	pubKey1, _ := ioutil.ReadFile(EnvelopePublickeyLocation)

	type args struct {
		cipherText      string
		node            []v1.NodeSelectorRequirement
		iHubPubKeys     map[string][]byte
		tagPrefix       string
		attestationType string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test 1",
			args: args{
				cipherText:      "",
				node:            []v1.NodeSelectorRequirement{},
				iHubPubKeys:     map[string][]byte{"key1": pubKey1},
				tagPrefix:       "isecl.",
				attestationType: "SGX",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckAnnotationAttrib(tt.args.cipherText, tt.args.node, tt.args.iHubPubKeys, tt.args.tagPrefix, tt.args.attestationType); got != tt.want {
				t.Errorf("CheckAnnotationAttrib() = %v, want %v", got, tt.want)
			}
		})
	}
}
