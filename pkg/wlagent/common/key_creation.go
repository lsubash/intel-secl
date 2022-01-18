/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/tpmprovider"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"

	"github.com/pkg/errors"
)

const secretKeyLength int = 20

var (
	log    = cLog.GetDefaultLogger()
	secLog = cLog.GetSecurityLogger()
)

// tpmCertifiedKeySetup calls the TPM helper library to export a binding or signing keypair
func createKey(config *config.Configuration, usage int, t tpmprovider.TpmFactory) (tpmck *tpmprovider.CertifiedKey, err error) {
	log.Trace("common/key_creation:createKey() Entering")
	defer log.Trace("common/key_creation:createKey() Leaving")
	if usage != tpmprovider.Binding && usage != tpmprovider.Signing {
		return nil, errors.New("common/key_creation:createKey()  Incorrect KeyUsage parameter - needs to be signing or binding")
	}
	secretbytes, err := crypt.GetRandomBytes(secretKeyLength)
	if err != nil {
		return nil, err
	}

	switch usage {
	case tpmprovider.Binding:
		config.BindingKeySecret = hex.EncodeToString(secretbytes)
	case tpmprovider.Signing:
		config.SigningKeySecret = hex.EncodeToString(secretbytes)
	}

	secLog.Infof("common/key_creation:createKey() %s, Calling CreateCertifiedKey of tpm library to create and certify signing or binding key", message.SU)

	tpm, err := t.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrap(err, "error while getting tpm provider")
	}

	defer tpm.Close()

	switch usage {
	case tpmprovider.Binding:
		tpmck, err = tpm.CreateBindingKey(config.BindingKeySecret)
	case tpmprovider.Signing:
		tpmck, err = tpm.CreateSigningKey(config.SigningKeySecret)
	}
	if err != nil {
		return nil, err
	}

	return tpmck, nil
}

//Todo: for now, this will always overwrite the file. Should be a parameter
// that forces overwrite of file.
func writeCertifiedKeyToDisk(tpmck *tpmprovider.CertifiedKey, filepath string) error {
	log.Trace("common/key_creation:writeCertifiedKeyToDisk() Entering")
	defer log.Trace("common/key_creation:writeCertifiedKeyToDisk() Leaving")

	if tpmck == nil {
		return errors.New("common/key_creation:writeCertifiedKeyToDisk() certifiedKey struct is empty")
	}

	// Marshal the certified key to json
	certifiedKeyJson, err := json.MarshalIndent(tpmck, "", "    ")
	if err != nil {
		return errors.Wrap(err, "common/key_creation:writeCertifiedKeyToDisk() Error while marshalling tpm certified key to json")
	}

	// create a file and write the json value to it and finally close it
	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, constants.DefaultFilePerms)
	if err != nil {
		return errors.New("common/key_creation:writeCertifiedKeyToDisk() Could not create file Error:" + err.Error())
	}
	_, err = f.WriteString(string(certifiedKeyJson))
	if err != nil {
		return errors.Wrap(err, "common/key_creation:writeCertifiedKeyToDisk() Failed to write json")
	}
	_, err = f.WriteString("\n")
	if err != nil {
		return errors.Wrap(err, "common/key_creation:writeCertifiedKeyToDisk() Failed to write end of data")
	}
	defer func() {
		derr := f.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	return nil
}

// GenerateKey creates a TPM binding or signing key
// It uses the AiKSecret that is saved in the Workload Agent configuration
// that is obtained from the trust agent, a random secret and uses the TPM
// to generate a keypair that is tied to the TPM
func GenerateKey(config *config.Configuration, usage int, t tpmprovider.TpmFactory, configPath string) error {
	log.Trace("common/key_creation:GenerateKey() Entering")
	defer log.Trace("common/key_creation:GenerateKey() Leaving")

	if t == nil {
		return errors.New("common/key_creation:GenerateKey() Connection to TPM library not initialized")
	} else if usage != tpmprovider.Binding && usage != tpmprovider.Signing {
		return errors.Errorf("common/key_creation:GenerateKey() Invalid key usage")
	}

	// Create and certify the signing or binding key
	certKey, err := createKey(config, usage, t)
	if err != nil {
		return errors.Wrap(err, "common/key_creation:GenerateKey() Error while creating binding/signing key")
	}

	// Get the name of signing or binding key files depending on input parameter
	var filename string
	switch usage {
	case tpmprovider.Binding:
		filename = constants.BindingKeyFileName
	case tpmprovider.Signing:
		filename = constants.SigningKeyFileName
	}

	// Join configuration path and signing or binding file name
	filepath := path.Join(configPath, filename)

	// Writing certified key value to file path
	err = writeCertifiedKeyToDisk(certKey, filepath)
	if err != nil {
		return errors.Wrapf(err, "common/key_creation:GenerateKey() Error while writing key to the file %s", filepath)
	}

	log.Info("common/key_creation:GenerateKey() Key is stored at file path : ", filepath)
	return nil
}

// ValidateKey validates if a key of type binding or signing is actually configured in
// the Workload Agent
// Installed method of the CertifiedKey checks if there is a key already installed.
// For now, this only checks for the existence of the file and does not check if
// contents of the file are indeed correct
func ValidateKey(usage int, configPath string) error {
	log.Trace("common/key_creation:ValidateKey() Entering")
	defer log.Trace("common/key_creation:ValidateKey() Leaving")

	// Get the name of signing or binding key files depending on input parameter
	var filename string
	switch usage {
	case tpmprovider.Binding:
		filename = constants.BindingKeyFileName
	case tpmprovider.Signing:
		filename = constants.SigningKeyFileName
	}

	// Join configuration path and signing or binding file name
	filepath := path.Join(configPath, filename)
	fi, err := os.Stat(filepath)
	if err != nil {
		return errors.Wrapf(err, "common/key_creation:ValidateKey() Could not find file %s", filepath)
	}
	if fi == nil && !fi.Mode().IsRegular() {
		return errors.New("common/key_creation:ValidateKey() Key file path is incorrect")
	}
	return nil
}
