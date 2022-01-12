/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package model

type CertTypes string

func (cct CertTypes) String() string {
	return string(cct)
}

const (
	CaCertTypesRootCa CertTypes = "root"
	CertTypesSaml     CertTypes = "saml"
)

// GetUniqueCertTypes returns a list of unique certificate types as strings
func GetUniqueCertTypes() []string {
	return []string{CaCertTypesRootCa.String(),
		CertTypesSaml.String()}
}
