/*
Copyright © 2022 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package controllers

import (
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/version"
	"net/http"
)

type VersionController struct {
}

func (controller VersionController) GetVersion(w http.ResponseWriter, _ *http.Request) {
	defaultLog.Trace("controllers/version:getVersion() Entering")
	defer defaultLog.Trace("controllers/version:getVersion() Leaving")

	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	_, err := w.Write([]byte(version.GetVersion()))
	if err != nil {
		defaultLog.WithError(err).Error("Could not write version to response")
	}
}
