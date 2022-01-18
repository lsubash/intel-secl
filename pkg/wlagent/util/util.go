/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/json"
	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/hostinfo"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/tpmprovider"
	model "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
	"github.com/intel-secl/intel-secl/v5/pkg/wlagent/constants"
	"io/ioutil"
	"path"

	"github.com/spf13/viper"

	"github.com/pkg/errors"
)

var log = cLog.GetDefaultLogger()
var secLog = cLog.GetSecurityLogger()

// GetTpmInstance method is used to get an instance of TPM to perform various tpm operations
func GetTpmInstance() (tpmprovider.TpmProvider, error) {
	log.Trace("util/util:GetTpmInstance() Entering")
	defer log.Trace("util/util:GetTpmInstance() Leaving")
	tpmFactory, err := tpmprovider.LinuxTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		return nil, errors.Wrap(err, "util/util:GetTpmInstance() Could not create TPM Factory")
	}

	vmStartTpm, err := tpmFactory.NewTpmProvider()

	return vmStartTpm, nil
}

// UnwrapKey method is used to unbind a key using TPM
func UnwrapKey(tpmWrappedKey []byte) ([]byte, error) {
	log.Trace("util/util:UnwrapKey() Entering")
	defer log.Trace("util/util:UnwrapKey() Leaving")

	if len(tpmWrappedKey) == 0 {
		return nil, errors.New("util/util:UnwrapKey() tpm wrapped key is empty")
	}

	var certifiedKey tpmprovider.CertifiedKey
	t, err := GetTpmInstance()
	defer t.Close()
	if err != nil {
		return nil, errors.Wrap(err, "util/util:UnwrapKey() Could not establish connection to TPM")
	}
	log.Debug("util/util:UnwrapKey() Reading the binding key certificate")
	bindingKeyFilePath := path.Join(constants.ConfigDirPath, constants.BindingKeyFileName)
	bindingKeyCert, fileErr := ioutil.ReadFile(bindingKeyFilePath)
	if fileErr != nil {
		return nil, errors.New("util/util:UnwrapKey() Error while reading the binding key certificate")
	}

	log.Debug("util/util:UnwrapKey() Unmarshalling the binding key certificate file contents to TPM CertifiedKey object")
	jsonErr := json.Unmarshal(bindingKeyCert, &certifiedKey)
	if jsonErr != nil {
		return nil, errors.New("util/util:UnwrapKey() Error unmarshalling the binding key file contents to TPM CertifiedKey object")
	}

	log.Debug("util/util:UnwrapKey() Binding key deserialized")
	secLog.Infof("util/util:UnwrapKey() %s, Binding key getting decrypted", message.SU)
	key, unbindErr := t.Unbind(&certifiedKey, viper.GetString(constants.BindingKeySecretViperKey), tpmWrappedKey)
	if unbindErr != nil {
		return nil, errors.Wrap(unbindErr, "util/util:UnwrapKey() error while unbinding the tpm wrapped key")
	}
	log.Debug("util/util:UnwrapKey() Unbinding TPM wrapped key was successful, return the key")
	return key, nil
}

// GetPlatformInfo retrieves the platform information for the host via HostInfo struct
func GetPlatformInfo() *model.HostInfo {
	// get the platform-info
	hInfo := hostinfo.NewHostInfoParser().Parse()

	if hInfo == nil {
		log.Error("util/GetHostInfo() unable to retrieve Platform Info")
		return nil
	}
	return hInfo
}
