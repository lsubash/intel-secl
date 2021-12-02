/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package fds

import (
	"crypto/x509"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"net/http"
	"net/url"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/util"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/model/fds"
)

var log = commLog.GetDefaultLogger()

type Client interface {
	SearchHosts(*fds.HostFilterCriteria) ([]byte, error)
	GetVersion() (string, error)
}

func NewClient(fdsURL *url.URL, aasBaseURL *url.URL, certs []x509.Certificate, username, password string) Client {
	return &fdsClient{
		BaseURL:    fdsURL,
		AasBaseURL: aasBaseURL,
		CaCerts:    certs,
		Username:   username,
		Password:   password,
	}
}

type fdsClient struct {
	BaseURL    *url.URL
	AasBaseURL *url.URL
	CaCerts    []x509.Certificate
	Username   string
	Password   string
}

func (f *fdsClient) SearchHosts(hostFilterCriteria *fds.HostFilterCriteria) ([]byte, error) {
	log.Trace("clients/fds:SearchHosts() Entering")
	defer log.Trace("clients/fds:SearchHosts() Leaving")

	hostsURL, _ := url.Parse("hosts")
	reqURL := f.BaseURL.ResolveReference(hostsURL)
	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create new request")
	}
	req.Header.Set("Accept", "application/json")
	query := req.URL.Query()

	if hostFilterCriteria.HostName != "" {
		query.Add("hostName", hostFilterCriteria.HostName)
	}

	if hostFilterCriteria.NameContains != "" {
		query.Add("nameContains", hostFilterCriteria.NameContains)
	}

	if hostFilterCriteria.HardwareId != uuid.Nil {
		query.Add("hostHardwareId", hostFilterCriteria.HardwareId.String())
	}

	req.URL.RawQuery = query.Encode()

	log.Debugf("SearchHosts: %s", req.URL.RawQuery)

	hostDetails, err := util.SendRequest(req, f.AasBaseURL.String(), f.Username, f.Password, f.CaCerts)
	if err != nil {
		log.Error("clients/fds:SearchHosts() Error while sending request")
		return nil, err
	}

	return hostDetails, nil
}
