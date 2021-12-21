/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"crypto/x509"
	"net/url"

	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
)

var log = commLog.GetDefaultLogger()

type KBSClient interface {
	CreateKey(*kbs.KeyRequest) (*kbs.KeyResponse, error)
	GetKey(string, string) (*kbs.KeyTransferResponse, error)
	TransferKey(string) (string, string, error)
	TransferKeyWithSaml(string, string) (*kbs.KeyTransferResponse, error)
	TransferKeyWithEvidence(string, string, string, *kbs.KeyTransferRequest) (*kbs.KeyTransferResponse, error)
}

func NewKBSClient(aasURL, kbsURL *url.URL, username, password, token string, certs []x509.Certificate) KBSClient {
	return &kbsClient{
		AasURL:   aasURL,
		BaseURL:  kbsURL,
		UserName: username,
		Password: password,
		JwtToken: token,
		CaCerts:  certs,
	}
}

type kbsClient struct {
	AasURL   *url.URL
	BaseURL  *url.URL
	UserName string
	Password string
	JwtToken string
	CaCerts  []x509.Certificate
}
