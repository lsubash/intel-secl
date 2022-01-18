/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"encoding/json"
	"github.com/google/uuid"
	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	pinfo "github.com/intel-secl/intel-secl/v5/pkg/lib/hostinfo"
	wlsModel "github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	wlsclient "github.com/intel-secl/intel-secl/v5/pkg/wlagent/clients"
	"strings"
)

var log = cLog.GetDefaultLogger()
var secLog = cLog.GetSecurityLogger()

// imageKeyID is a map of keyID and imageUUID, the secureoverlay2 driver is unaware of image uuid.
// Secureoverlay has only information of keyID of each layer.
// The secure docker daemon passes the keyid to workload agent for fetching the key
// which in turn usees the image uuid for fetching the flavor key
var imageKeyID map[string]string

// OutFlavor is a struct containing return code and image flavor as output from RPC call
type OutFlavor struct {
	ReturnCode  bool
	ImageFlavor string
}

func getKeyID(keyUrl string) string {

	keyUrlSplit := strings.Split(keyUrl, "/")
	keyID := keyUrlSplit[len(keyUrlSplit)-2]
	return keyID
}

func init() {
	imageKeyID = make(map[string]string)
}

// Fetch method is used to fetch image flavor key from workload-service
// Input Parameters: imageID string, Hardware UUID
// Return: returns a boolean value to the secure docker plugin.
// true if the flavorkey is fetched successfully, else return false.
func Fetch(imageID string) (string, bool) {
	log.Trace("flavor/flavor:Fetch Entering")
	defer log.Trace("flavor/flavor:Fetch Leaving")
	var flavorKeyInfo wlsModel.FlavorKey

	log.Debug("Retrieving host hardware UUID...")
	hostInfo := pinfo.NewHostInfoParser().Parse()
	if hostInfo == nil {
		log.Error("flavor/key_retrieval:Fetch() unable to get the host info")
		return "", false
	}

	hardwareUUID := hostInfo.HardwareUUID
	log.Debugf("The host hardware UUID is :%s", hardwareUUID)
	// get image flavor key from workload service
	flavorKeyInfo, err := wlsclient.GetImageFlavorKey(imageID, hardwareUUID)
	if err != nil {
		secLog.WithError(err).Error("flavor/flavor:Fetch() Error while retrieving the image flavor")
		return "", false
	}

	if flavorKeyInfo.Flavor.Meta.ID == uuid.Nil {
		log.Infof("Flavor does not exist for the image: %s", imageID)
		return "", true
	}

	if flavorKeyInfo.Flavor.EncryptionRequired {
		keyID := getKeyID(flavorKeyInfo.Flavor.Encryption.KeyURL)
		imageKeyID[keyID] = imageID
		if len(flavorKeyInfo.Key) == 0 {
			secLog.Error("Could not retrieve flavor Key, Host is untrusted or key doesnt exist with associated flavor")
			return "", false
		}
	}

	f, err := json.Marshal(flavorKeyInfo.Flavor)
	if err != nil {
		log.WithError(err).Error("flavor/flavor:Fetch() Error while marshalling flavor")
		return "", false
	}

	return string(f), true
}
