/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v5/pkg/tagent/config"

	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	taModel "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type RequestHandler interface {
	GetTpmQuote(quoteRequest *taModel.TpmQuoteRequest, aikCertPath string, measureLogFilePath string, ramfsDir string) (*taModel.TpmQuoteResponse, error)
	GetHostInfo(platformInfoFilePath string) (*taModel.HostInfo, error)
	GetAikDerBytes(aikCertPath string) ([]byte, error)
	DeployAssetTag(*taModel.TagWriteRequest) error
	GetBindingCertificateDerBytes(bindingKeyCertificatePath string) ([]byte, error)
	DeploySoftwareManifest(manifest *taModel.Manifest, varDir string) error
	GetApplicationMeasurement(manifest *taModel.Manifest, tBootXmMeasurePath string, logDirPath string) (*taModel.Measurement, error)
	ProvisionImaFiles(reprovisionFilePath string, provisionRequest *taModel.ReprovisionImaRequest) error
}

func NewRequestHandler(cfg *config.TrustAgentConfiguration) RequestHandler {
	return &requestHandlerImpl{
		cfg: cfg,
	}
}

type requestHandlerImpl struct {
	cfg *config.TrustAgentConfiguration
}

type EndpointError struct {
	Message    string
	StatusCode int
}

func (e EndpointError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}
