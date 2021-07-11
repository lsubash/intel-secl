/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package fds

import (
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
)

func (f *fdsClient) GetVersion() (string, error) {
	log.Trace("clients/fds:SearchHosts() Entering")
	defer log.Trace("clients/fds:SearchHosts() Leaving")

	versionURL, _ := url.Parse("version")
	reqURL := f.BaseURL.ResolveReference(versionURL)
	response, err := http.Get(reqURL.String())
	if err != nil {
		return "", errors.Wrap(err, "Failed to create new request")
	}

	responseBytes, err := ioutil.ReadAll(response.Body)
	return string(responseBytes), nil
}
