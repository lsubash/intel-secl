/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/verifier/workload"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
	"github.com/pkg/errors"
	"time"
)

var reportMap = map[string]string{

	"f1c45b32-53cb-4982-9962-b04724f86b21": ` {
        "instance_manifest": {
            "instance_info": {
                "instance_id": "bd06385a-5530-4644-a510-e384b8c3323a",
                "host_hardware_uuid": "00964993-89c1-e711-906e-00163566263e",
                "image_id": "773e22da-f687-47ca-89e7-5df655c60b7b"
            },
            "image_encrypted": true
        },
        "policy_name": "Intel VM Policy",
        "results": [
            {
                "rule": {
                    "rule_name": "EncryptionMatches",
                    "markers": [
                        "IMAGE"
                    ],
                    "expected": {
                        "name": "encryption_required",
                        "value": true
                    }
                },
                "flavor_id": "3a3e1ccf-2618-4a0d-8426-fb7acb1ebabc",
                "trusted": true
            }
        ],
        "trusted": true,
        "data": "eyJpbnN0YW5jZV9tYW5pZmVzdCI6eyJpbnN0YW5jZV9pbmZvIjp7Imluc3RhbmNlX2lkIjoiYmQwNjM4NWEtNTUzMC00NjQ0LWE1MTAtZTM4NGI4YzMzMjNhIiwiaG9zdF9oYXJkd2FyZV91dWlkIjoiMDA5NjQ5OTMtODljMS1lNzExLTkwNmUtMDAxNjM1NjYyNjNlIiwiaW1hZ2VfaWQiOiI3NzNlMjJkYS1mNjg3LTQ3Y2EtODllNy01ZGY2NTVjNjBiN2IifSwiaW1hZ2VfZW5jcnlwdGVkIjp0cnVlfSwicG9saWN5X25hbWUiOiJJbnRlbCBWTSBQb2xpY3kiLCJyZXN1bHRzIjpbeyJydWxlIjp7InJ1bGVfbmFtZSI6IkVuY3J5cHRpb25NYXRjaGVzIiwibWFya2VycyI6WyJJTUFHRSJdLCJleHBlY3RlZCI6eyJuYW1lIjoiZW5jcnlwdGlvbl9yZXF1aXJlZCIsInZhbHVlIjp0cnVlfX0sImZsYXZvcl9pZCI6IjNhM2UxY2NmLTI2MTgtNGEwZC04NDI2LWZiN2FjYjFlYmFiYyIsInRydXN0ZWQiOnRydWV9XSwidHJ1c3RlZCI6dHJ1ZX0=",
        "hash_alg": "SHA-256",
        "cert": "-----BEGIN CERTIFICATE-----\nMIIEkTCCA3mgAwIBAgIJAPZIe4/J1rS4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\nBAMTEG10d2lsc29uLXBjYS1haWswHhcNMTkwNDMwMDM0MjI3WhcNMjkwNDI3MDM0\nMjI3WjAlMSMwIQYDVQQDDBpDTj1TaWduaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJHAH8O1VLhSIxy3pa5MUemtrJQw\nONd3+JzO6wq5hRYf5iBOK1ADbAF0iLjGV0CXWYNVIQgCahqmn5TQGGFjsLZ4XpDy\nUmCkYsMzqZxcjGZr/dgmXci50v9o2m7FoQgt1eo6JEcB3NYwCkEHzEkx0Ns6cFul\nx9wsYUgU0CwRt2lderLJFs8O5ojKuID+6+bfJM+mGNmGfMudFDsSyJbw8uVqJN/w\njQNGhFIpapLabxcPrhwlUAf5efjldeKgoP/QFdOBolRT3R5HiCc4A28EwR+KpCsz\n2SnPtI7rJHiPZlsNYncroXSKkB2S7EXiFEnd0uME6Mhicg0dZ0U+yC+vEA8CAwEA\nAaOCAcwwggHIMA4GA1UdDwEB/wQEAwIGwDCBnQYHVQSBBQMCKQSBkf9UQ0eAFwAi\nAAvMr4Y5+2EueRqQYi93bUkUj0N+bRncFS9UlxfZLDbcpwAEAP9VqgAAAAAAFALJ\nAAAABQAAAAABAAcAKAAIMgAAIgALTGEwky4u3fkb0E2zIcrc6ernZN3qq3Ma4658\n19uM8tkAIgAL9bsq9DzOiSKNpNm6DNfh9SmdEZvY8cpOW+G/Ue0DLbswggEUBghV\nBIEFAwIpAQSCAQYAFAALAQCFbPimpFjbGCJ6+psrVrxu2vqY631OYyLg8xGaDdAh\nY2SEaZUub93Jp/UfmZt3bP2inG4kKhvmKAiIHHlRf+aFCZ7SJMNGrh9o6TwmVaiz\nT35YVjZpO6xFEmdv5eQIxYKCmE301QwHrvymqW+TeCPe8BWRtCcXA2Vuskf18xI9\nVafYJUSHC9NSk85538AbztXgJidOUgARpTweDJt8u3v2lkpZlhRk3+7kOkyI3xv+\nvvKeWaQokfkJiCWTCNT7vSVc14YKs4o4bXnYiwzpFtHuypMcBtcliDh12xnowGHs\nx7helzw/ue1ACQRHHhDuPDY1VECmuN/qUNRXunWrJTvXMA0GCSqGSIb3DQEBCwUA\nA4IBAQADtwxXKk6PaXKB1iFSyUAY4IQF3296xcYddGy6XxyLZH+ePkr/xmzBPbSW\nlzYgnDaJ+bohzJqio+abm1ovRahlEgCHLZatHvIcWbBqFpLgMw1Z2xTulcwuGtW/\nOSMKM/LfU1T8dyDisXojTsby2Rxj2wsfWC3GXrPWOkefkEC4qVyo7VXOVuAxZhPw\ni3ysiWPjTDnEHAJVqCtqsWSZHSwcpDeRnntMQ8GV6K+4TCZ6rcD9a47ArlvCKKoI\nNKFXK5xW8/xwaVikyMBAqlXjjWnS4HcIh7BYTj55Dxy9qjJJDBfqgXi7t8t7no2F\nBZRD/3W7YmEExAsSvX8Y4naY4rpU\n-----END CERTIFICATE-----\n",
        "signature": "KcC6UI6C5vLDrBIQx/EU9ceNPJDP6fjrF7F+6pxJYoA50rwx7ZI0ULbL2HXQiD82oQltqzj/n0KzY8JxY0PhIuG1w2vF58xOOzlxFP4w3BF6PSMW7wggwr1sj0TvlLcoyO7jXiK4nIlNfOqj6VaS/ynzMDGSSZvYkQ46SvAVdd0k57jHNG4TBrlqW+PWrM3xsqUrUeSVWCTH13G7qk6P4yPBnSerbmMBT4zuiodL+B0FsSlXorE6bZ/zt2N836DtL42eIbc7YXigLtvmE48M15kzO3cfQAsHva5MPx0S0rHsVSYaD5vFiQdRKBIdEmZWcZK2rfXUHwVAloWQAjZaCQ=="
    }`,
}

var reportRetrieveCols = []string{"id", "trust_report", "signed_data"}
var reportAllCols = []string{"id", "created", "expiration", "instance_id", "saml", "trust_report", "signed_data"}

type MockReportStore struct {
	Mock        sqlmock.Sqlmock
	ReportStore *postgres.ReportStore
}

type Report struct {
	ID          uuid.UUID                    `gorm:"type:uuid;primary_key;"`
	CreatedAt   time.Time                    `gorm:"column:created;not null"`
	Expiration  time.Time                    `gorm:"column:expiration;not null"`
	InstanceID  string                       `gorm:"type:uuid;not null"`
	Saml        string                       `gorm:"column:saml;not null"`
	TrustReport workload.InstanceTrustReport `json:"trust_report" sql:"type:JSONB"`
	SignedData  crypt.SignedData             `json:"signed_data" sql:"type:JSONB"`
}

// Create mocks Report Create Response
func (store *MockReportStore) Create(re *model.Report) (*model.Report, error) {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectBegin()

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	store.Mock.ExpectQuery(`INSERT INTO "report" (.+)`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(newUuid.String()))

	store.Mock.ExpectCommit()

	return store.ReportStore.Create(re)
}

// Retrieve mocks Report Retrieve Response
func (store *MockReportStore) Retrieve(reportId uuid.UUID) (*model.Report, error) {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	// mock for returned objects
	for k, v := range reportMap {
		var r Report
		err := json.Unmarshal([]byte(v), &r)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
		}
		var rReportBytes, _ = json.Marshal(&r.TrustReport)
		var rSignedDataBytes, _ = json.Marshal(&r.SignedData)
		store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \("report"."id" = \$1\)`).
			WithArgs(k).
			WillReturnRows(sqlmock.NewRows(reportRetrieveCols).
				AddRow(r.ID.String(), rReportBytes, rSignedDataBytes))
	}

	var report1 Report
	err := json.Unmarshal([]byte(reportMap["f1c45b32-53cb-4982-9962-b04724f86b21"]), &report1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}

	var rReportBytes, _ = json.Marshal(&report1.TrustReport)
	var rSignedDataBytes, _ = json.Marshal(&report1.SignedData)
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \("report"."id" = \$1\)`).
		WithArgs("f1c45b32-53cb-4982-9962-b04724f86b21").
		WillReturnRows(sqlmock.NewRows(reportRetrieveCols).
			AddRow("f1c45b32-53cb-4982-9962-b04724f86b21", rReportBytes, rSignedDataBytes))

	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \("report"."id" = \$1\)`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27").WillReturnError(errors.New(commErr.RowsNotFound))

	return store.ReportStore.Retrieve(reportId)
}

// Delete deletes Report from the store
func (store *MockReportStore) Delete(reportId uuid.UUID) error {
	// any of the options below can be applied

	store.Mock.MatchExpectationsInOrder(false)
	store.Mock.ExpectBegin()

	deleteResult := sqlmock.NewResult(1, 1)
	store.Mock.ExpectExec(`DELETE FROM "report"  WHERE "report"."id" = \$1`).
		WithArgs("f1c45b32-53cb-4982-9962-b04724f86b21").
		WillReturnResult(deleteResult)

	var report1 Report
	err := json.Unmarshal([]byte(reportMap["f1c45b32-53cb-4982-9962-b04724f86b21"]), &report1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}

	var rReportBytes, _ = json.Marshal(&report1.TrustReport)
	var rSignedDataBytes, _ = json.Marshal(&report1.SignedData)
	var rSaml, _ = json.Marshal(&report1.Saml)

	store.Mock.ExpectQuery(`SELECT \* FROM "report"  WHERE \("report"."id" = \$1\) ORDER BY "report"."id" ASC LIMIT 1`).
		WithArgs("f1c45b32-53cb-4982-9962-b04724f86b21").
		WillReturnRows(sqlmock.NewRows(reportAllCols).
			AddRow("f1c45b32-53cb-4982-9962-b04724f86b21", time.Now().AddDate(0, 0, -1), time.Now().AddDate(0, 0, -1), "bd06385a-5530-4644-a510-e384b8c3323a", rSaml, rReportBytes, rSignedDataBytes))

	store.Mock.ExpectExec(`DELETE FROM "report"  WHERE "report"."id" = \$1`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27").WillReturnError(errors.New(commErr.RowsNotFound))

	store.Mock.ExpectCommit()
	return store.ReportStore.Delete(reportId)
}

// Search returns a filtered list of report
func (store *MockReportStore) Search(criteria *model.ReportFilter) ([]model.Report, error) {

	store.Mock.MatchExpectationsInOrder(false)
	//Search without filter
	allRows := sqlmock.NewRows(reportRetrieveCols)

	for _, v := range reportMap {
		var r Report
		err := json.Unmarshal([]byte(v), &r)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
		}
		var rReportBytes, _ = json.Marshal(&r.TrustReport)
		var rSignedDataBytes, _ = json.Marshal(&r.SignedData)
		allRows.AddRow(r.ID.String(), rReportBytes, rSignedDataBytes)
	}

	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"`).
		WillReturnRows(allRows)

	store.Mock.ExpectQuery(`SELECT \* FROM "report"  WHERE \("report"."id" = \$1\) ORDER BY "report"."id" ASC LIMIT 1`).
		WithArgs("f1c45b32-53cb-4982-9962-b04724f86b21").
		WillReturnRows(allRows)

	var report1 Report
	err := json.Unmarshal([]byte(reportMap["f1c45b32-53cb-4982-9962-b04724f86b21"]), &report1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}
	var rReportBytes, _ = json.Marshal(&report1.TrustReport)
	var rSignedDataBytes, _ = json.Marshal(&report1.SignedData)

	//Search with filer report ID
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \(id = \$1\)`).
		WithArgs("f1c45b32-53cb-4982-9962-b04724f86b21").
		WillReturnRows(sqlmock.NewRows(reportRetrieveCols).
			AddRow("f1c45b32-53cb-4982-9962-b04724f86b21", rReportBytes, rSignedDataBytes))

	//Search with non existing report ID
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \(id = \$1\)`).
		WithArgs("ee37c360-7eae-4250-a677-6ee12adce8e2").
		WillReturnRows(sqlmock.NewRows([]string{"id", "trust_report", "signed_data"}))

	//Search with filer hostHardwareId
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \(trust_report -> 'instance_manifest' -> 'instance_info' ->> 'host_hardware_uuid' = \$1\)`).
		WithArgs("00964993-89c1-e711-906e-00163566263e").
		WillReturnRows(sqlmock.NewRows(reportRetrieveCols).
			AddRow("f1c45b32-53cb-4982-9962-b04724f86b21", rReportBytes, rSignedDataBytes))

	//Search with filer instance_id
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM /"report/"  WHERE \(trust_report -> 'instance_manifest' -> 'instance_info' -> 'instance_id' = \$1\)`).
		WithArgs("bd06385a-5530-4644-a510-e384b8c3323a").
		WillReturnRows(sqlmock.NewRows(reportRetrieveCols).
			AddRow("f1c45b32-53cb-4982-9962-b04724f86b21", rReportBytes, rSignedDataBytes))

	//Search with filer numberOfDays
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \(CAST\(created AS TIMESTAMP\) >= CAST\(\$1 AS TIMESTAMP\)\) AND \(CAST\(created AS TIMESTAMP\) < CAST\($2 AS TIMESTAMP\)\)`).
		WithArgs("2021-06-21 13:23:11.782213", "2021-06-21 13:23:11.782213").
		WillReturnRows(sqlmock.NewRows(reportRetrieveCols).
			AddRow("f1c45b32-53cb-4982-9962-b04724f86b21", rReportBytes, rSignedDataBytes))

	//Search with filer fromDate and toDate
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \(CAST\(created AS TIMESTAMP\) >= CAST\(\$1 AS TIMESTAMP\)\) AND \(CAST\(created AS TIMESTAMP\) < CAST\(\$2 AS TIMESTAMP\)\)`).
		WithArgs("2021-06-01 00:00:00", "2021-06-24 2021-06-24").
		WillReturnRows(sqlmock.NewRows(reportRetrieveCols).
			AddRow("f1c45b32-53cb-4982-9962-b04724f86b21", rReportBytes, rSignedDataBytes))

	//Search with non-existing report ID
	store.Mock.ExpectQuery(`SELECT id, trust_report, signed_data FROM "report"  WHERE \("report"."id" = \$1\)`).
		WithArgs("c44b26f0-1381-40d5-8f09-670ea6b64915").
		WillReturnRows(sqlmock.NewRows(reportRetrieveCols))

	return store.ReportStore.Search(criteria)
}

// NewMockReportStore initializes the mock datastore
func NewMockReportStore() *MockReportStore {
	datastore, mock := postgres.NewSQLMockDataStore()

	return &MockReportStore{
		Mock:        mock,
		ReportStore: postgres.NewReportStore(datastore),
	}
}
