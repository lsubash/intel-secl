/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// This file contains utility functions that support a 'rules' ability to add 'faults'
// to a 'RuleResult'.
//

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

func newPcrValueMissingFault(bank types.SHAAlgorithm, pcrIndex types.PcrIndex) Fault {
	return Fault {
		Name:        FaultPcrValueMissing,
		Description: fmt.Sprintf("Host report does not include required PCR %d, bank %s", pcrIndex, bank),
		PcrIndex:    &pcrIndex,
	}
}

func newPcrValueMismatchFault(pcrIndex types.PcrIndex, expectedPcr types.Pcr, actualPcr types.Pcr) Fault {
	return Fault {
		Name:             FaultPcrValueMismatch + string(actualPcr.PcrBank),
		Description:      fmt.Sprintf("Host PCR %d with value '%s' does not match expected value '%s'", pcrIndex, actualPcr.Value, expectedPcr.Value),
		PcrIndex:         &pcrIndex,
		ExpectedPcrValue: &expectedPcr.Value,
		ActualPcrValue:   &actualPcr.Value,
	}
}

func newPcrEventLogMissingExpectedEntries(eventLogEntry *types.EventLogEntry) Fault {
	return Fault {
		Name: FaultPcrEventLogMissingExpectedEntries,
		Description: fmt.Sprintf("Module manifest for PCR %d missing %d expected entries", eventLogEntry.PcrIndex, len(eventLogEntry.EventLogs)),
		PcrIndex: &eventLogEntry.PcrIndex,
		MissingEntries: eventLogEntry.EventLogs,
	}
}

func newPcrEventLogMissingFault(pcrIndex types.PcrIndex) Fault {
	return Fault{
		Name:        FaultPcrEventLogMissing,
		Description: fmt.Sprintf("Host report does not include a PCR Event Log for PCR %d", pcrIndex),
		PcrIndex:    &pcrIndex,
	}
}

func newPcrEventLogContainsUnexpectedEntries(eventLogEntry *types.EventLogEntry) Fault {
	return Fault {
		Name: FaultPcrEventLogContainsUnexpectedEntries,
		Description: fmt.Sprintf("Module manifest for PCR %d contains %d unexpected entries", eventLogEntry.PcrIndex, len(eventLogEntry.EventLogs)),
		PcrIndex: &eventLogEntry.PcrIndex,
		UnexpectedEntries: eventLogEntry.EventLogs,
	}
}

func newXmlEventLogMissingFault(flavorId uuid.UUID) Fault {
	return Fault{
		Name:        FaultXmlMeasurementLogMissing,
		Description: fmt.Sprintf("Host report does not contain XML Measurement log for flavor %s.", flavorId),
	}
}

func newXmlMeasurementValueMismatch(expectedCumulativeHash string, actualCumulativeHash string) Fault {
	return Fault{
		Name: FaultXmlMeasurementValueMismatch,
		Description: fmt.Sprintf("Host XML measurement log final hash with value '%s' does not match expected value '%s'", actualCumulativeHash, expectedCumulativeHash),
		ExpectedValue: &expectedCumulativeHash,
		ActualValue: &actualCumulativeHash,
	}
}

func newFlavorSignatureVerificationFailed(flavorId uuid.UUID) Fault {
	return Fault{
		Name: FaultFlavorSignatureVerificationFailed,
		Description: fmt.Sprintf("Signature verification failed for flavor with id %s", flavorId),
	}
}

func newXmlMeasurementLogInvalidFault() Fault {
	return Fault {
		Name: FaultXmlMeasurementLogInvalid,
		Description: "Unable to parse one of the measurements present in HostManifest",
	}
}

func newPcrManifestMissingFault() Fault {
	return Fault {
		Name: FaultPcrManifestMissing,
		Description: "Host report does not include a PCR Manifest",
	}
}