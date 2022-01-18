/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/tpmprovider"
	wlaModel "github.com/intel-secl/intel-secl/v5/pkg/model/wlagent"

	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"

	"github.com/pkg/errors"
)

// CreateRequest method constructs the payload for signing-key/binding-key registration.
func CreateRequest(aikPemFilePath string, key []byte) (*wlaModel.RegisterKeyInfo, error) {
	log.Trace("common/key_registration:CreateRequest() Entering")
	defer log.Trace("common/key_registration:CreateRequest() Leaving")

	var httpRequestBody *wlaModel.RegisterKeyInfo
	var keyInfo tpmprovider.CertifiedKey
	var tpmVersion string
	var err error

	err = json.Unmarshal(key, &keyInfo)
	if err != nil {
		return httpRequestBody, errors.Wrap(err, "common/key_registration:CreateRequest() Error while unmarshalling tpm Certified Key")
	}

	//set tpm version
	if keyInfo.Version == tpmprovider.V20 {
		tpmVersion = constants.TpmVersion20
	} else {
		tpmVersion = constants.TpmVersion12
	}

	aikCert, err := ioutil.ReadFile(aikPemFilePath)
	if err != nil {
		return httpRequestBody, errors.Wrap(err, "common/key_registration:CreateRequest() Error reading certificate file.")
	}
	aikDer, _ := pem.Decode(aikCert)
	_, err = x509.ParseCertificate(aikDer.Bytes)
	if err != nil {
		return httpRequestBody, errors.Wrap(err, "common/key_registration:CreateRequest() Error parsing certificate file.")
	}

	// TODO remove hack below. This hack was added since key stored on disk needs to be modified
	// so that HVS can register the key.
	// ISECL - 3506 opened to address this issue later
	//construct request body
	httpRequestBody = &wlaModel.RegisterKeyInfo{
		PublicKeyModulus:       keyInfo.PublicKey,
		TpmCertifyKey:          keyInfo.KeyAttestation[2:],
		TpmCertifyKeySignature: keyInfo.KeySignature,
		AikDerCertificate:      aikDer.Bytes,
		NameDigest:             append(keyInfo.KeyName[1:], make([]byte, 34)...),
		TpmVersion:             tpmVersion,
		OsType:                 strings.Title(runtime.GOOS),
	}

	return httpRequestBody, nil
}

//WriteKeyCertToDisk method is used to write the signing-key/binding-key certificate to specified path on the system
func WriteKeyCertToDisk(keyCertPath string, aikPem []byte) error {
	log.Trace("common/WriteKeyCertToDisk:WriteKeyCertToDisk() Entering")
	defer log.Trace("common/WriteKeyCertToDisk:WriteKeyCertToDisk() Leaving")
	file, err := os.OpenFile(keyCertPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, constants.DefaultFilePerms)
	if err != nil {
		return errors.Wrap(err, "common/key_registration:WriteKeyCertToDisk() Error creating file.")
	}
	if err = pem.Encode(file, &pem.Block{Type: constants.PemCertificateHeader, Bytes: aikPem}); err != nil {
		return errors.Wrap(err, "common/key_registration:WriteKeyCertToDisk() Error writing certificate to file.")
	}
	return nil

}
