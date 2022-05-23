/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/base64"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"

	"github.com/intel-secl/intel-secl/v5/pkg/wpm/config"
	consts "github.com/intel-secl/intel-secl/v5/pkg/wpm/constants"

	kbsc "github.com/intel-secl/intel-secl/v5/pkg/clients/kbs"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
)

var (
	assetTagReg = regexp.MustCompile(`^[a-zA-Z0-9]+:[a-zA-Z0-9]+$`)
)

func NewKBSClient(config *config.Configuration, trustedCAPath string) (kbsc.KBSClient, error) {
	log.Trace("pkg/wpm/util/encrypt.go:NewKBSClient() Entering")
	defer log.Trace("pkg/wpm/util/encrypt.go:NewKBSClient() Leaving")

	if config == nil {
		return nil, errors.New("pkg/util/fetch_key.go:NewKBSClient() Error loading WPM configuration")
	}

	aasUrl, err := url.Parse(config.AASApiUrl)
	if err != nil {
		return nil, errors.Wrap(err, "pkg/util/fetch_key.go:NewKBSClient() Error parsing AAS url")
	}

	kbsUrl, err := url.Parse(config.KBSApiUrl)
	if err != nil {
		return nil, errors.Wrap(err, "pkg/util/fetch_key.go:NewKBSClient() Error parsing KBS url")
	}

	//Load trusted CA certificates
	caCerts, err := crypt.GetCertsFromDir(trustedCAPath)
	if err != nil {
		return nil, errors.Wrap(err, "pkg/util/fetch_key.go:NewKBSClient() Error loading CA certificates")
	}
	kbsClient := kbsc.NewKBSClient(aasUrl, kbsUrl, config.WPM.Username, config.WPM.Password, "", caCerts)

	return kbsClient, nil
}

//FetchKey from kbs
func FetchKey(keyID string, assetTag string, KBSApiUrl string, envelopePublickeyLocation string, kbsClient kbsc.KBSClient) ([]byte, string, error) {
	log.Trace("pkg/wpm/util/encrypt.go:FetchKey() Entering")
	defer log.Trace("pkg/wpm/util/encrypt.go:FetchKey() Leaving")

	if kbsClient == nil {
		return nil, "", errors.New("pkg/wpm/util/fetch_key.go:FetchKey() Invalid KBSClient")
	}
	if KBSApiUrl == "" {
		return nil, "", errors.New("pkg/util/fetch_key.go:FetchKey() Invalid KBS url")
	}

	var keyUrlString string
	//If key ID is not specified, create a new key
	if len(strings.TrimSpace(keyID)) <= 0 {
		var keyInfo kbs.KeyInformation
		var keyRequest kbs.KeyRequest

		keyInfo.Algorithm = consts.KbsEncryptAlgo
		keyInfo.KeyLength = consts.KbsKeyLength
		keyRequest.KeyInformation = &keyInfo
		if assetTagReg.MatchString(strings.TrimSpace(assetTag)) {
			keyRequest.Usage = assetTag
		} else {
			log.Warn("pkg/wpm/util/fetch_key.go:FetchKey() Asset Tags provided are not in valid format. Skipping associating usage policy")
		}
		log.Debug("pkg/wpm/util/fetch_key.go:FetchKey() Creating new key")
		keyResponse, err := kbsClient.CreateKey(&keyRequest)
		if err != nil {
			return nil, "", errors.Wrap(err, "pkg/wpm/util/fetch_key.go:FetchKey() Error creating the image encryption key")
		}

		keyID = keyResponse.KeyInformation.ID.String()
		log.Debugf("pkg/util/fetch_key.go:FetchKey() keyID: %s", keyID)
		keyUrlString = keyResponse.TransferLink

	} else {
		//Build the key URL, to be inserted later on when the image flavor is created
		keyUrl, err := url.Parse(KBSApiUrl + "/keys/" + keyID + "/transfer")
		if err != nil {
			return nil, "", errors.Wrap(err, "Error building KBS key URL")
		}
		keyUrlString = keyUrl.String()
	}

	log.Debugf("pkg/util/fetch_key.go:FetchKey() keyUrl: %s", keyUrlString)

	pubKey, err := ioutil.ReadFile(envelopePublickeyLocation)
	if err != nil {
		return nil, "", errors.Wrap(err, "pkg/util/fetch_key.go:FetchKey() Error reading envelop public key")
	}
	//Retrieve key using key ID
	keyValue, err := kbsClient.GetKey(keyID, string(pubKey))
	if err != nil {
		return nil, "", errors.Wrap(err, "pkg/wpm/util/fetch_key.go:FetchKey() Error retrieving the image encryption key")
	}
	log.Info("pkg/wpm/util/fetch_key.go:FetchKey() Successfully retrieved key")
	log.Debugf("pkg/util/fetch_key.go:FetchKey() %s", keyUrlString)

	wrappedKey, err := base64.StdEncoding.DecodeString(keyValue.WrappedKey)
	if err != nil {
		return nil, "", errors.Wrap(err, "pkg/util/fetch_key.go:FetchKey() Error decoding the image encryption key")
	}
	return wrappedKey, keyUrlString, nil
}
