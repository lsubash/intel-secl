/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package workload

import (
	"errors"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/pkg/instance"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/validation"
	flvr "github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"net/url"
)

// Verify verifies a manifest against a flavor.
// manifest and flavor are both interface{}, but must be able to be type asserted (downcasted) to one of the following:
// manifest:
// - *instance.Manifest
// flavor:
// - *flavor.ImageFlavor
// More types will be supported as the feature set is expanded in this library
// Verify returns an interface{} which is a concrete type of any of the following:
// - *InstanceTrustReport
func Verify(manifest interface{}, flavor interface{}, flavorSigningCertDirPath, trustedCAsDirPath string, skipFlavorSignatureVerification bool) (interface{}, error) {
	var flavorPart string
	var err error
	flavorVal := flavor.(*flvr.SignedImageFlavor)
	manifestVal, ok := manifest.(*instance.Manifest)
	if !ok {
		return nil, errors.New("supplied manifest is not an instance Manifest")
	}

	// input validation for manifest
	if err = validation.ValidateUUIDv4(manifestVal.InstanceInfo.InstanceID); err != nil {
		return nil, errors.New("Invalid input : VmID must be a valid UUID")
	}

	if err = validation.ValidateHardwareUUID(manifestVal.InstanceInfo.HostHardwareUUID); err != nil {
		return nil, errors.New("Invalid input : Host hardware UUID must be valid")
	}

	if err = validation.ValidateUUIDv4(manifestVal.InstanceInfo.InstanceID); err != nil {
		return nil, errors.New("Invalid input : ImageID must be a valid UUID")
	}

	//input validation for flavor
	if err = validation.ValidateUUIDv4((flavorVal.ImageFlavor.Meta.ID).String()); err != nil {
		return nil, errors.New("Invalid input : FlavorID must be a valid UUID")
	}

	if !isValidFlavorPart(flavorVal.ImageFlavor.Meta.Description.FlavorPart) {
		return nil, errors.New("Invalid input :flavor part must be IMAGE or CONTAINER_IMAGE")
	}

	if flavorVal.ImageFlavor.Encryption != nil && flavorVal.ImageFlavor.Encryption.KeyURL != "" {
		uriValue, _ := url.Parse(flavorVal.ImageFlavor.Encryption.KeyURL)
		protocol := make(map[string]byte)
		protocol["https"] = 0
		if validateURLErr := validation.ValidateURL(flavorVal.ImageFlavor.Encryption.KeyURL, protocol, uriValue.RequestURI()); validateURLErr != nil {
			return nil, errors.New("Invalid key URL format")
		}

		if validateDigestErr := validation.ValidateBase64String(flavorVal.ImageFlavor.Encryption.Digest); validateDigestErr != nil {
			return nil, errors.New("Invalid base64 string for the digest")
		}
	}

	switch flavor := flavor.(type) {
	case *flvr.SignedImageFlavor:
		// assert manifest as VM Manifest
		flavorPart = flavor.ImageFlavor.Meta.Description.FlavorPart
		if flavorPart == "IMAGE" {
			return VerifyVM(manifestVal, flavor, flavorSigningCertDirPath, trustedCAsDirPath, skipFlavorSignatureVerification)
		} else if flavorPart == "CONTAINER_IMAGE" {
			return VerifyContainer(manifestVal, flavor, flavorSigningCertDirPath, trustedCAsDirPath, skipFlavorSignatureVerification)
		} else {
			return nil, errors.New("unrecognized flavor type")
		}
	default:
		return nil, errors.New("unrecognized flavor type")
	}
}

// VerifyVM explicity verifies a VM Manifest against a VM ImageFlavor, and returns a VMTrustReport
func VerifyVM(manifest *instance.Manifest, flavor *flvr.SignedImageFlavor, flavorSigningCertsDir, trustedCAsDir string, skipFlavorSignatureVerification bool) (*InstanceTrustReport, error) {
	var result []Result

	r := newEncryptionMatches("IMAGE", flavor.ImageFlavor.EncryptionRequired)
	trust, faults := r.Apply(manifest)
	result = append(result, Result{Rule: r, FlavorID: flavor.ImageFlavor.Meta.ID.String(), Faults: faults, Trusted: trust})

	if !skipFlavorSignatureVerification {
		flavorIntegrityRule := newFlavorIntegrityMatches(flavorSigningCertsDir, trustedCAsDir)
		trust, faults = flavorIntegrityRule.Apply(*flavor)
		result = append(result, Result{Rule: flavorIntegrityRule, FlavorID: flavor.ImageFlavor.Meta.ID.String(), Faults: faults, Trusted: trust})
	}
	//get consolidated trust status
	isTrusted := getTrustStatus(result)
	// TrustReport is Trusted if all rule applications result in trust == true
	return &InstanceTrustReport{*manifest, "Intel VM Policy", result, isTrusted}, nil
}

// VerifyContainer explicity verifies a Container Manifest against a Container ImageFlavor, and returns a ContainerTrustReport
func VerifyContainer(manifest *instance.Manifest, flavor *flvr.SignedImageFlavor, flavorSigningCertsDir, trustedCAsDir string, skipFlavorSignatureVerification bool) (*InstanceTrustReport, error) {
	var result []Result

	encryptionRule := newEncryptionMatches("CONTAINER_IMAGE", flavor.ImageFlavor.EncryptionRequired)
	trust, faults := encryptionRule.Apply(manifest)
	result = append(result, Result{Rule: encryptionRule, FlavorID: flavor.ImageFlavor.Meta.ID.String(), Faults: faults, Trusted: trust})

	integrityRule := newIntegrityMatches("CONTAINER_IMAGE", flavor.ImageFlavor.IntegrityEnforced)
	trust, faults = integrityRule.Apply(manifest)
	result = append(result, Result{Rule: integrityRule, FlavorID: flavor.ImageFlavor.Meta.ID.String(), Faults: faults, Trusted: trust})

	if !skipFlavorSignatureVerification {
		flavorIntegrityRule := newFlavorIntegrityMatches(flavorSigningCertsDir, trustedCAsDir)
		trust, faults = flavorIntegrityRule.Apply(*flavor)
		result = append(result, Result{Rule: flavorIntegrityRule, FlavorID: flavor.ImageFlavor.Meta.ID.String(), Faults: faults, Trusted: trust})
	}
	//get consolidated trust status
	isTrusted := getTrustStatus(result)
	// TrustReport is Trusted if all rule applications result in trust == true
	return &InstanceTrustReport{*manifest, "Intel Container Policy", result, isTrusted}, nil
}

//returns consolidated trust status in case of multiple rule validation
func getTrustStatus(result []Result) bool {
	isTrusted := true
	//if no result is generated
	if len(result) <= 0 {
		return false
	}
	for _, element := range result {
		isTrusted = isTrusted && element.Trusted
	}
	return isTrusted
}

//isValidFlavorPart method checks if the flavor part is of type IMAGE, CONTAINER_IMAGE
func isValidFlavorPart(flavor string) bool {
	flavorPart := [...]string{"IMAGE", "CONTAINER_IMAGE"}
	for _, a := range flavorPart {
		if a == flavor {
			return true
		}
	}
	return false
}
