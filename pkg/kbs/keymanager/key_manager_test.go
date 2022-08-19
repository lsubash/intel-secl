/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"os"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/kbs/config"
)

var token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"

var cacertPath = "cacert.pem"
var certPath = "certificate.crt"
var keyPath = "privateKey.pem"

var cacert = `-----BEGIN CERTIFICATE-----
MIIELDCCApSgAwIBAgIBADANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
AxMFQ01TQ0EwHhcNMjExMjE0MTI0OTMwWhcNMjYxMjE0MTI0OTMwWjBHMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
TDEOMAwGA1UEAxMFQ01TQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
gQCeH5Xdd9xIy90KdG4spRFWamFq0CYbAOM+vYmIJ6uAHqna+1CvtjuW9vdEBhBi
6ehDZbvEptUmp3w8/MtFQ6Kl4BxE5UKOOr9odiZiMD29IZQKif2SRwlMONAvAlZb
ma3x/c7z4W6mhjf4FBpnXwq5PlPCNo+E0DSWuNUQx/dB4hVhXX7SL8pOBPLFsCz2
pYCjCIpyoRHAtKRgA/iLgkVRTPt5oVw1vQHDzk9g5V5TkGsG3w9URIc+t6ad6W5k
utYonErNe2w90Gcle7FQx8W7g7799othl8Uo9ae4uj+Zvo95ILCb1sYBbeTo/U52
mPsCpp+am8pHeQCrH0sQ76vK0N+NtHZlInHZzfWBh3XFHtt2l072mWtndfWNb6Qz
DbJ4XVQuqT2hK4qWo1xBAR9BN+/VBTia6KlG2JygXIuXSOpRoi88TdXHj/8EDbJR
PNLx9iUlJMf85bS0ZlEtR0jgAoRbuNxQVR7gIdxBZeB9FLgWbOBKwoDcLe1UiCp9
vekCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQEMBQADggGBAGXcD7drlEdReqXSakuWUwsdstwP7TLyvW/xdyrlQGyo
cuHdOri4XhaMcb4S7TFTtN8/e9l1mLCspftBRoiTyg4w+vrA1LFF2vA4ZOY3C41I
KZiWLu/3mPDDD3fofLI/P+abu4+JYqgjozIb5D7H7KEIJ8VYDRKMrU0xSiDqXx31
4RubSFeO1eK0d7YagI7LY/lJd8GzOT4VHLrUsIEBlvK/1MqvVkmFFjhijbOVpK34
Pbl84PSTwn1g2o+NwVYyzsMqBGktppw24/EClBMyJ6PUWZPHK8ciW7R841MriL6/
n3SDZkWn523Sm0a+Ns+A51J0OGrMY0jn/TvYXZBF5a5amTU+2j2hT5FCgWw3lqNW
i5H5A1xmQ1XqCT4wa+2P6W6IyPtq5uGKR1/lknKClRcaNjg6uWzkEoBW0Bi6zkie
bFIQr/GeJeDLzs6CYNs/WGboTfy5zKUqbbLUVOM8+6wcoNLM1n9WhiSoPV8pbAz8
qIplPNOMbtluK6PJ+398DQ==
-----END CERTIFICATE-----`

var cert = `-----BEGIN CERTIFICATE-----
MIIDRTCCAi0CFBs1K0K+dAt5O3iJLxxIXQhGPCNBMA0GCSqGSIb3DQEBCwUAMF8x
CzAJBgNVBAYTAmluMRIwEAYDVQQIDAl0YW1pbG5hZHUxEDAOBgNVBAcMB2NoZW5u
YWkxDDAKBgNVBAoMA0FNSTEOMAwGA1UECwwFSVNFQ0wxDDAKBgNVBAMMA2ticzAe
Fw0yMjA0MTQxMDIyMjBaFw0zMjA0MTExMDIyMjBaMF8xCzAJBgNVBAYTAmluMRIw
EAYDVQQIDAl0YW1pbG5hZHUxEDAOBgNVBAcMB2NoZW5uYWkxDDAKBgNVBAoMA0FN
STEOMAwGA1UECwwFSVNFQ0wxDDAKBgNVBAMMA2ticzCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALovC2ElCiPhap68pp+/q4tWOmBVBwA2i2eyukqk/eEc
wbB6M11CsJYL2pqqSar2D1RuTEC6Y5FrFYPwNNBjmTs2olJaiZuV5VgZDWeKAMDf
LwsExLLiVX3Ynt7Cfgm+FkEMZj/1J1KGJ1OnPyboAUhgkp47cJOPqxofOWSTJUFw
EawNZc2/8XteEw4bC2F+JLFS4jPoHY0UxW0ebdBRaZkT4DdDi8RvOV7/HhC3JTbC
JifMVnw+c/Z73+Ag01aSZBE1M7jx0+u2FSpIS5eb88Iaodm/VJrigEmNzBA7qj5R
yioGeiTtrkm4buU3ZQ98PDrvAvvN4HDOeazxoPn+VV0CAwEAATANBgkqhkiG9w0B
AQsFAAOCAQEAl+G/W1Vlbt/jj2Nc59Jf1TxWtkWPYfUyI7tXDCGweYRtrVLdrIWl
0XOoVSULMHayjcm78EaASq0NtHuT4cVhrvBrTAQ/gLHFL8uQj/i3uiB5LgJGsxJN
vUjvg+vxf+vlKV9szBpqauqnbcQ+frAvNiD2iT1nw/Mqc+W8odqD5/CGNq0RHqNv
KaKJxIDAuPZce2tMONWiVpuTcWOF+5ujFj73EfsQvNVFsdh6uEVpkaF8Y6OI2ywX
S/Fr1M5LGPeILR9fTL3aFH+5/j6hHv6XZjrO71f59K2z3up7ad14Q9vYo6sckGb/
Mv8iNyBwXpciVZOKJM27Pdao324N0xdfGA==
-----END CERTIFICATE-----`

var privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAui8LYSUKI+Fqnrymn7+ri1Y6YFUHADaLZ7K6SqT94RzBsHoz
XUKwlgvamqpJqvYPVG5MQLpjkWsVg/A00GOZOzaiUlqJm5XlWBkNZ4oAwN8vCwTE
suJVfdie3sJ+Cb4WQQxmP/UnUoYnU6c/JugBSGCSnjtwk4+rGh85ZJMlQXARrA1l
zb/xe14TDhsLYX4ksVLiM+gdjRTFbR5t0FFpmRPgN0OLxG85Xv8eELclNsImJ8xW
fD5z9nvf4CDTVpJkETUzuPHT67YVKkhLl5vzwhqh2b9UmuKASY3MEDuqPlHKKgZ6
JO2uSbhu5TdlD3w8Ou8C+83gcM55rPGg+f5VXQIDAQABAoIBACpC23ZljfOvCyCU
+c1xGGM8Y2vSYRBvUR1suFSRNv+OI3kHg/k7VhH5BtnspWQlDj2/+5cFt+wePngA
YjybHwEN2bKP0oR6deCVbzF9ZcZh4q/BmVRxg65ZKVavFyTm/O4u/lauMwrMYMjg
Qbl3GDNxmFZKb7dO+SuowsJNlDtR7V4TQMBkTRZPhPQma1joPvahM6sBa6j01pfI
kYnhmyqeWDb0E9JwCHEcpybClDKfAnOiR/BUa1xs6ikXmgpkl+aBm3qq9rzBly7g
5Uw2dQ/45KpvEHA58nEFZHS40eB4UqYQEv/vf/aC1MXKwdSq9roflIws2Q5zzQua
m2yFIpECgYEA8G6noQqe/4nFqlIHtWcYZqW12Y3ywRE5rlNF4fL5uqgkaLm2735D
l73gIDKBRvTQQcjhJmBDrR9UuybS0vlcmAWdHkLXS1WiXAfSMXblY12yTMNAc5Jm
KEiwTB227q1TdPrq8X34upg3f4eRFYQJWS/Z3TwDlalNvaSk8sA+z0MCgYEAxj0u
K2cCJmuhcHMwdkYODEMXlzQV3+tK0X9S+3lWxT10aJl91POR8MVPT0+NlTPHQ6mp
Y2pyNkVaqCpfFm0Q3JTTl7GawBKYXuIHniK2rgTC1yFOtqR+xqPe/R+D3Kd3BFRw
QJS9v1f4GhohQf51ppY6jFGPapfsMhiM/WbTbt8CgYEAkgqkx60r5wxIhKxPAmEc
8Ty2uO8ABUXxQ3JRgG2WQ0re0r374H1RkVpESUpkPDV4Sn06RZUzhnUBgqySYpQV
KkI+raLsI1ZgyIX3pxQRQcooA3iWLZ0/cDi23YUvGMsvZl8DVqyt6KmNDGnMNsV8
6C+opjlN9Bpink7j4o/jlwECgYAXFejahRRrBP236rIqE95u7yFAKoChovUDkKBJ
SMgiEBYOWFGfCv5j25Zw1gLW7UC3UHq5aRwD1e/IxaZtJiZgibRaZgRvebrk0c2x
TLmZalSGWQqhmmZpG4xMTe89MwNZLbwkyS2Pqt7pq0FUPh3VWIlY7eaVszt+Wf2R
RPg6YQKBgQCaO2z6UCTPAk0pVKiigen3M71lSUxvY5UhodR/kTc+6w9z/YP5UiZ1
xGLRF/cI5VIBcfnCShf4IhmNvfaXGNuWG4zOI7er+u/UbkFSMvRuCxl5LpPQdG8H
7FBn0IogLklR4ORxVYzATNypLEbzmWhznKL5j6hzKd7vHa1Yv8C8GQ==
-----END RSA PRIVATE KEY-----`

func TestNewKeyManager(t *testing.T) {

	createTestFiles()

	type args struct {
		cfg *config.Configuration
	}
	tests := []struct {
		name    string
		args    args
		want    KeyManager
		wantErr bool
	}{
		{
			name: "Validate create new key manager with valid kmipclient, should create a new keymanager",
			args: args{
				cfg: &config.Configuration{
					AASBaseUrl:  "https://aas.com:8444/aas/v1/",
					CMSBaseURL:  "https://cms.com:8445/cms/v1/",
					EndpointURL: "https://localhost:9443/kbs/v1",
					KeyManager:  "kmip",
					Kmip: config.KmipConfig{
						Version:                   "2.0",
						ServerIP:                  "http://127.0.0.1",
						ServerPort:                "8771",
						Hostname:                  "KbsHost",
						Username:                  "root",
						Password:                  "P@ssw0rd",
						ClientKeyFilePath:         "./privateKey.pem",
						ClientCertificateFilePath: "./certificate.crt",
						RootCertificateFilePath:   "./cacert.pem",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Validate create new key manager with empty clientkey path, should fail to create new keymanager",
			args: args{
				cfg: &config.Configuration{
					AASBaseUrl:  "https://aas.com:8444/aas/v1/",
					CMSBaseURL:  "https://cms.com:8445/cms/v1/",
					EndpointURL: "https://localhost:9443/kbs/v1",
					KeyManager:  "kmip",
					Kmip: config.KmipConfig{
						Version:                   "2.0",
						ServerIP:                  "http://127.0.0.1",
						ServerPort:                "8771",
						Hostname:                  "KbsHost",
						Username:                  "root",
						Password:                  "P@ssw0rd",
						ClientKeyFilePath:         "",
						ClientCertificateFilePath: "test/certificate.crt",
						RootCertificateFilePath:   "test/ca.pem",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Validate create new key manager with empty KeyManager type, should fail to create new keymanager",
			args: args{
				cfg: &config.Configuration{
					AASBaseUrl:  "https://aas.com:8444/aas/v1/",
					CMSBaseURL:  "https://cms.com:8445/cms/v1/",
					EndpointURL: "https://localhost:9443/kbs/v1",
					KeyManager:  "",
					Kmip: config.KmipConfig{
						Version:                   "2.0",
						ServerIP:                  "http://127.0.0.1",
						ServerPort:                "8771",
						Hostname:                  "KbsHost",
						Username:                  "root",
						Password:                  "P@ssw0rd",
						ClientKeyFilePath:         "./test/private.pem",
						ClientCertificateFilePath: "./test/certificate.crt",
						RootCertificateFilePath:   "./test/ca.pem",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKeyManager(tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeyManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	//Cleaning the test files
	os.Remove(cacertPath)
	os.Remove(certPath)
	os.Remove(keyPath)
}

func createTestFiles() {

	// check if cacert file exists
	_, err := os.Stat(cacertPath)

	// create file if not exists
	if os.IsNotExist(err) {
		file, err := os.Create(cacertPath)
		if err != nil {
			return
		}
		defer file.Close()
	}
	cacertFile, err := os.OpenFile(cacertPath, os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer cacertFile.Close()

	// Write some text line-by-line to file.
	_, err = cacertFile.WriteString(cacert)
	if err != nil {
		return
	}

	// check if certificate file exists
	_, err = os.Stat(certPath)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(certPath)
		if err != nil {
			return
		}
		defer file.Close()
	}

	certFile, err := os.OpenFile(certPath, os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer certFile.Close()

	// Write some text line-by-line to file.
	_, err = certFile.WriteString(cert)
	if err != nil {
		return
	}

	// check if Private key file exists
	_, err = os.Stat(keyPath)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(keyPath)
		if err != nil {
			return
		}
		defer file.Close()
	}

	keyFile, err := os.OpenFile(keyPath, os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer keyFile.Close()

	// Write some text line-by-line to file.
	_, err = keyFile.WriteString(privateKey)
	if err != nil {
		return
	}
}
