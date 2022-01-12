/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
)

func NewFakeCertificatesPathStore() *crypt.CertificatesPathStore {
	// Mock path to create new certificate
	rootCaPath := "../domain/mocks/resources/root/"
	//Path for any certificate containing file, so instead of creating new use existing one
	samlCaCertPath := "../domain/mocks/resources/SamlCaCert.pem"

	return &crypt.CertificatesPathStore{
		model.CaCertTypesRootCa.String(): crypt.CertLocation{
			CertPath: rootCaPath,
		},
		model.CertTypesSaml.String(): crypt.CertLocation{
			CertPath: samlCaCertPath,
		},
	}
}

func NewFakeCertificatesStore() *crypt.CertificatesStore {

	// Mock path to create new certificate
	rootCaPath := "../domain/mocks/resources/root/"
	//Path for any certificate containing file, so instead of creating new use existing one
	samlCaCertPath := "../domain/mocks/resources/SamlCaCert.pem"

	return &crypt.CertificatesStore{
		model.CaCertTypesRootCa.String(): &crypt.CertificateStore{
			CertPath:     rootCaPath,
			Certificates: nil,
		},
		model.CertTypesSaml.String(): &crypt.CertificateStore{
			CertPath:     samlCaCertPath,
			Certificates: nil,
		},
	}
}
