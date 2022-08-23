/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"fmt"
	"net/http"
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	taModel "github.com/intel-secl/intel-secl/v5/pkg/model/ta"
)

func (handler *requestHandlerImpl) ProvisionImaFiles(reprovisionFilePath string, provisionRequest *taModel.ReprovisionImaRequest) error {
	log.Trace("common/provision_ima_files:ProvisionImaFiles() Entering")
	defer log.Trace("common/provision_ima_files:ProvisionImaFiles() Leaving")

	err := validation.ValidateStrings(provisionRequest.Files)
	if err != nil {
		log.WithError(err).Errorf("common/provision_ima_files:ProvisionImaFiles() %s - Invalid file names %s", message.InvalidInputBadParam, provisionRequest.Files)
		return &EndpointError{Message: "Invalid file names", StatusCode: http.StatusBadRequest}
	}

	reprovisionFile, err := os.OpenFile(reprovisionFilePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.WithError(err).Errorf("common/provision_ima_files:ProvisionImaFiles() Error in opening file %s", reprovisionFilePath)
		return &EndpointError{Message: "Error in opening file", StatusCode: http.StatusBadRequest}
	}
	defer func() {
		derr := reprovisionFile.Close()
		if derr != nil {
			log.WithError(derr).Errorf("common/provision_ima_files:ProvisionImaFiles() Error in closing %s", reprovisionFilePath)
		}
	}()

	for _, fileName := range provisionRequest.Files {
		// If file or folder does not exist to provision, then log the details, don't throw error
		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			log.Debugf("common/provision_ima_files:ProvisionImaFiles() %s does not exist to provision", fileName)
			continue
		}

		// write the list to file
		_, err = fmt.Fprintln(reprovisionFile, fileName)
		if err != nil {
			log.WithError(err).Errorf("common/provision_ima_files:ProvisionImaFiles() Error in Writing %s to file", fileName)
			return &EndpointError{Message: "Error in writing to file", StatusCode: http.StatusBadRequest}
		}
	}

	return nil
}
