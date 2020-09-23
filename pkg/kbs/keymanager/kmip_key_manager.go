/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/kmipclient"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type KmipManager struct {
	client *kmipclient.KmipClient
}

func (km *KmipManager) CreateKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:CreateKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:CreateKey() Leaving")

	var err error
	var kmipId string

	if request.KeyInformation.Algorithm == constants.CRYPTOALG_AES {
		kmipId, err = km.client.CreateSymmetricKey(constants.KMIP_CRYPTOALG_AES, request.KeyInformation.KeyLength)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.Errorf("%s algorithm is not supported", request.KeyInformation.Algorithm)
	}

	keyAttributes := &models.KeyAttributes{
		ID:               uuid.New(),
		Algorithm:        request.KeyInformation.Algorithm,
		KeyLength:        request.KeyInformation.KeyLength,
		KmipKeyID:        kmipId,
		TransferPolicyId: request.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
		Label:            request.Label,
		Usage:            request.Usage,
	}

	return keyAttributes, nil
}

func (km *KmipManager) DeleteKey(attributes *models.KeyAttributes) error {
	defaultLog.Trace("keymanager/kmip_key_manager:DeleteKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:DeleteKey() Leaving")

	if attributes.KmipKeyID == "" {
		return errors.New("key is not created with KMIP key manager")
	}

	return km.client.DeleteSymmetricKey(attributes.KmipKeyID)
}

func (km *KmipManager) RegisterKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:RegisterKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:RegisterKey() Leaving")

	return nil, errors.New("register operation is not supported")
}

func (km *KmipManager) TransferKey(attributes *models.KeyAttributes) ([]byte, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:TransferKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:TransferKey() Leaving")

	if attributes.KmipKeyID == "" {
		return nil, errors.New("key is not created with KMIP key manager")
	}

	if attributes.Algorithm == constants.CRYPTOALG_AES {
		return km.client.GetSymmetricKey(attributes.KmipKeyID)
	} else {
		return nil, errors.Errorf("%s algorithm is not supported", attributes.Algorithm)
	}
}