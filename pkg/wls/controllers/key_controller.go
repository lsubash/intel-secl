/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/kbs"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	samlVerifier "github.com/intel-secl/intel-secl/v5/pkg/lib/saml"
	hvsmodel "github.com/intel-secl/intel-secl/v5/pkg/model/hvs"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	consts "github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/keycache"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type KeyController struct {
	CertStore *crypt.CertificatesStore
	config    *config.Configuration
}

func NewKeyController(cfg *config.Configuration, certStore *crypt.CertificatesStore) *KeyController {
	return &KeyController{config: cfg,
		CertStore: certStore,
	}
}

func (kcon *KeyController) RetrieveKey(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	log.Trace("controller/key_controller:RetrieveKey() Entering")
	defer log.Trace("controller/key_controller:RetrieveKey() Leaving")

	var formBody wls.RequestKey
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&formBody); err != nil {
		log.WithError(err).Errorf("controller/key_controller:RetrieveKey() %s : Failed to encode request body as Key", message.AppRuntimeErr)
		log.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Failed to retrieve key - JSON marshal error"}
	}
	// validate input format
	hwid := formBody.HwId
	if err := validation.ValidateHardwareUUID(hwid); err != nil {
		log.WithError(err).Errorf("controller/key_controller:RetrieveKey() %s : Invalid Hardware UUID format", message.InvalidInputProtocolViolation)
		log.Tracef("%+v", err)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid hardware UUID format"}
	}
	cLog := log.WithField("hardwareUUID", hwid)

	cLog.Debug("controller/key_controller:RetrieveKey() Retrieving  Key")

	keyUrl := formBody.KeyUrl
	// Check if flavor keyUrl is not empty
	if len(keyUrl) > 0 {
		key, err := transferKey(false, hwid, keyUrl, "", kcon.config, kcon.CertStore)
		if err != nil {
			cLog.WithError(err).Error("controller/key_controller:RetrieveKey() Error while retrieving key")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
		}

		// got key data
		returnKey := wls.ReturnKey{
			Key: key,
		}

		cLog.Info("controller/key_controller:RetrieveKey() Successfully retrieved Key")
		secLog.Infof("Key successfully retrieved  by: %s", r.RemoteAddr)
		return returnKey, http.StatusCreated, nil
	} else {
		defaultLog.Infof("controller/key_controller:RetrieveKey() keyUrl is empty")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "keyUrl is empty"}
	}
}

// Verifies host and retrieves key from KBS
// getFlavor is true for the images API and false for the keys API
// id is only required when using the images API
func transferKey(getFlavor bool, hwid string, kUrl string, id string, cfg *config.Configuration, certStore *crypt.CertificatesStore) ([]byte, error) {
	var endpoint, funcName, retrievalErr string
	if getFlavor {
		endpoint = "resource/images"
		funcName = "RetrieveFlavorandKey()"
		retrievalErr = "Failed to retrieve Flavor/Key for Image"
	} else {
		endpoint = "resource/keys"
		funcName = "RetrieveKey()"
		retrievalErr = "Failed to retrieve Key for Image"
	}
	// we have key URL
	// post HVS with hardwareUUID
	// extract key_id from KeyUrl
	cLog := log.WithField("hardwareUUID", hwid).WithField("keyUrl", kUrl)
	if getFlavor {
		cLog = cLog.WithField("id", id)
	}
	cLog.Debugf("%s:%s KeyUrl is present", endpoint, funcName)
	keyUrl, err := url.Parse(kUrl)
	if err != nil {
		cLog.WithError(err).Errorf("%s:%s %s : KeyUrl is malformed", endpoint, funcName, message.InvalidInputProtocolViolation)
		log.Tracef("%+v", err)
		return nil, errors.New(retrievalErr + " - KeyUrl is malformed")
	}
	re := regexp.MustCompile("(?i)([0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12})")
	keyID := re.FindString(keyUrl.Path)

	rootCAs := (*certStore)[model.CaCertTypesRootCa.String()].CertPath
	samlCAFile := (*certStore)[model.CertTypesSaml.String()].CertPath
	// retrieve host SAML report from HVS]
	vsClientFactory, err := hvsclient.NewVSClientFactoryWithUserCredentials(cfg.HVSApiUrl, cfg.AASApiUrl, cfg.WLS.Username, cfg.WLS.Password, rootCAs)
	if err != nil {
		cLog.WithError(err).Error("Error while instantiating VSClientFactory")
		return nil, errors.Wrap(err, "error while instantiating VSClientFactory")
	}

	reportsClient, err := vsClientFactory.ReportsClient()
	if err != nil {
		cLog.WithError(err).Error("Error while instantiating ReportsClient")
		return nil, errors.Wrap(err, "Error while instantiating ReportsClient")
	}

	reportCreateRequest := hvsmodel.ReportCreateRequest{
		HardwareUUID: uuid.MustParse(hwid),
	}
	saml, err := reportsClient.CreateSAMLReport(reportCreateRequest)
	if err != nil {
		cLog.WithError(err).Errorf("%s:%s %s : Failed to read HVS response body", endpoint, funcName, message.AppRuntimeErr)
		log.Tracef("%+v", err)
		return nil, errors.Wrap(err, retrievalErr+" - Failed to read HVS response")
	}

	// validate the response from HVS
	if err = validation.ValidateXMLString(string(saml)); err != nil {
		cLog.WithError(err).Errorf("%s:%s %s : HVS response validation failed", endpoint, funcName, message.AppRuntimeErr)
		return nil, errors.Wrap(err, retrievalErr+" - Invalid SAML report format received from HVS")
	}

	var samlStruct model.Saml
	cLog.WithField("saml", string(saml)).Debugf("%s:%s Successfully got SAML report from HVS", endpoint, funcName)
	err = xml.Unmarshal(saml, &samlStruct)
	if err != nil {
		cLog.WithError(err).Errorf("%s:%s %s : Failed to unmarshal host SAML report", endpoint, funcName, message.AppRuntimeErr)
		log.Tracef("%+v", err)
		return nil, errors.Wrap(err, retrievalErr+" - Failed to unmarshal host SAML report")
	}

	// verify saml cert chain
	verified := samlVerifier.VerifySamlSignature(string(saml), samlCAFile, rootCAs)
	if !verified {
		cLog.Errorf("%s:%s SAML certificate chain verification failed", endpoint, funcName)
		return nil, errors.New(retrievalErr + " - SAML signature or certificate chain verification failed")
	}

	for i := 0; i < len(samlStruct.Attribute); i++ {
		if samlStruct.Attribute[i].Name == "TRUST_OVERALL" {
			if samlStruct.Attribute[i].AttributeValue == "false" {
				return nil, errors.New(retrievalErr + " - Host is untrusted")
			} else {
				break
			}
		}
	}

	// check if the key is cached and retrieve it
	// try to obtain the key from the cache. If the key is not found in the cache,
	// then it will return and error.
	cachedKey, err := getKeyFromCache(hwid)
	if err == nil {
		cLog.Infof("%s:%s %s : Retrieved Key from in-memory cache. key ID: %s", endpoint, funcName, message.EncKeyUsed, cachedKey.ID)
		// check if the key cached is same as the one in the flavor
		if cachedKey.ID != "" && cachedKey.ID == keyID {
			return cachedKey.Bytes, nil
		}
	}

	//Load trusted CA certificates
	caCerts, err := crypt.GetCertsFromDir(rootCAs)
	if err != nil {
		cLog.WithError(err).Errorf("%s:%s %s : Failed to load CA certificates", endpoint, funcName, message.AppRuntimeErr)
		return nil, errors.Wrap(err, retrievalErr+" - Unable to load CA certificates")
	}

	baseUrl := strings.TrimSuffix(re.Split(kUrl, 2)[0], "keys/")
	kbsUrl, _ := url.Parse(baseUrl)
	//Initialize the KBS client
	kc := kbs.NewKBSClient(nil, kbsUrl, "", "", "", caCerts)

	// post to KBS client with saml
	cLog.Infof("%s:%s baseURL: %s, keyID: %s : start to retrieve key from KMS", endpoint, funcName, baseUrl, keyID)
	keyResp, err := kc.TransferKeyWithSaml(keyID, string(saml))
	if err != nil {
		cLog.WithError(err).Errorf("%s:%s %s : Failed to retrieve key from KMS", endpoint, funcName, message.AppRuntimeErr)
		return nil, errors.Wrap(err, "Failed to retrieve key ")
	}
	cLog.Infof("%s:%s Successfully got key from KBS", endpoint, funcName)

	key, err := base64.StdEncoding.DecodeString(keyResp.WrappedKey)
	if err != nil {
		cLog.WithError(err).Errorf("Failed to decode key")
		return nil, errors.Wrap(err, "Failed to decode key")
	}
	err = cacheKeyInMemory(hwid, keyID, key)
	if err != nil {
		cLog.WithError(err).Errorf("Failed to cache key")
	}
	return key, nil
}

// This method is used to check if the key for an image file is cached.
// If the key is cached, the method you return the key ID.
func getKeyFromCache(imageUUID string) (keycache.Key, error) {
	defaultLog.Trace("controller/key_controller:getKeyFromCache()")
	defer defaultLog.Trace("controller/key_controller:getKeyFromCache()")
	key, exists := keycache.Get(imageUUID)
	if exists && key.ID != "" && time.Now().Before(key.Expired) {
		return key, nil
	}
	return keycache.Key{}, errors.New("controller/key_controller:getKeyFromCache() key is not cached or expired")
}

// This method is used add the key to cache and map it with the image UUID
func cacheKeyInMemory(imageUUID string, keyID string, key []byte) error {
	defaultLog.Trace("controller/key_controller:cacheKeyInMemory() Entering")
	defer defaultLog.Trace("controller/key_controller:cacheKeyInMemory() Leaving")
	keycache.Store(imageUUID, keycache.Key{ID: keyID, Bytes: key, Created: time.Now(), Expired: time.Now().Add(time.Second * time.Duration(consts.DefaultKeyCacheSeconds))})
	return nil
}
