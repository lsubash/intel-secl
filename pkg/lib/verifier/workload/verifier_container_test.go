/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package workload

import (
	"encoding/json"
	"fmt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/pkg/instance"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/flavor"
	flvr "github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyContainer(t *testing.T) {
	var signedFlavor flvr.SignedImageFlavor
	containerFlavor, err := flavor.GetContainerImageFlavor("Hello-World:latest", true,
		"https://kbs.server.com:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", true, "https://notary.docker.io")
	assert.NoError(t, err)
	flavorBytes, _ := json.Marshal(containerFlavor)
	signedFlavorString, err := flavor.GetSignedImageFlavor(string(flavorBytes), "../test_data/workload/flavor-signing-key.pem")
	assert.NoError(t, err)
	manifest := instance.Manifest{InstanceInfo: instance.Info{InstanceID: "7B280921-83F7-4F44-9F8D-2DCF36E7AF33", HostHardwareUUID: "59EED8F0-28C5-4070-91FC-F5E2E5443F6B", ImageID: "670F263E-B34E-4E07-A520-40AC9A89F62D"}, ImageEncrypted: true, ImageIntegrityEnforced: true}
	json.Unmarshal([]byte(signedFlavorString), &signedFlavor)
	report, err := Verify(&manifest, &signedFlavor, "../test_data/workload/flavor-signing-cert.pem", "../test_data/workload/cacerts", false)
	assert.NoError(t, err)
	assert.NotNil(t, report)
	trustReport, ok := report.(*InstanceTrustReport)
	reportJSON, _ := json.Marshal(trustReport)
	fmt.Println(string(reportJSON))
	assert.True(t, ok)
	assert.True(t, trustReport.Trusted)
	assert.Len(t, trustReport.Results, 3)
	assert.Equal(t, trustReport.Results[0].Rule.Name(), "EncryptionMatches")
	assert.Equal(t, trustReport.Results[1].Rule.Name(), "IntegrityMatches")
	assert.Equal(t, trustReport.Results[2].Rule.Name(), "FlavorIntegrityMatches")
}
