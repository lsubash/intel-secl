/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain/models"
)

func NewFakeCertificatesPathStore() *models.CertificatesPathStore {
	// Mock path to create new certificate
	rootCaPath := "../domain/mocks/resources/root/"
	//Path for any certificate containing file, so instead of creating new use existing one
	samlCaCertPath := "../domain/mocks/resources/SamlCaCert.pem"

	return &models.CertificatesPathStore{
		models.CaCertTypesRootCa.String(): models.CertLocation{
			CertPath: rootCaPath,
		},
		models.CertTypesSaml.String(): models.CertLocation{
			CertPath: samlCaCertPath,
		},
	}
}

func NewFakeCertificatesStore() *models.CertificatesStore {

	// Mock path to create new certificate
	rootCaPath := "../domain/mocks/resources/root/"
	//Path for any certificate containing file, so instead of creating new use existing one
	samlCaCertPath := "../domain/mocks/resources/SamlCaCert.pem"

	return &models.CertificatesStore{
		models.CaCertTypesRootCa.String(): &models.CertificateStore{
			CertPath:     rootCaPath,
			Certificates: nil,
		},
		models.CertTypesSaml.String(): &models.CertificateStore{
			CertPath:     samlCaCertPath,
			Certificates: nil,
		},
	}
}
