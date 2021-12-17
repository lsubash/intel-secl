/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
	"github.com/pkg/errors"
	"time"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

var flavorMap = map[string]string{

	"dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f": `{"id": "dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f",
"created": "` + time.Now().Format(time.RFC3339) + `",
"label": "vm1-label-name",
"flavor_part": "IMAGE",
"flavor": {
    "meta": {
        "id": "dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f",
        "description": {
            "label": "vm1-label-name",
            "flavor_part": "IMAGE"
        }
    },
    "integrity": {},
    "encryption": {
        "key_url": "https://<kbs>:<kbs_port>/v1/keys/eb61b2e9-c7cd-4476-ac5f-71582c892112/transfer"
    },
    "integrity_enforced": false,
    "encryption_required": true
},
"signature": "N6J8yVIW5XT2KCudY2ShL7MlR2vffOg/olf/QFJKEiu5qAQri254G9LSkQ53CX3KrHQdNXpZdEcYfhunEnzIS3IOuihACCIBeN1Wz0ly0aWEraV21/e1kVeTOFuG8CJQqli00a1XkMFpn2Ik6NNbnwHQ/wUohxqjQ8MRunMP/Aj2rtWmZqDowL9ZjLpvS6Lk/AmfkPq/ai8zdv4uhoaIZZBs9SGQUPWiejhMeHNdjoP+t/D5SCuRJ7bsMBmw9F5ctUwgwS9gy9ThDUUhevQmoBpdFybkc+CU2xO0U/J+alqPO54nytPOLy7aU99SSD68N30jYkYdm+0ORXSMRk3raKcf9zAO8M3hWqctaKsfnMAJTaLvOzo7zNrIf1zoEfIAjJYWgjWUSgtzh5t0sPQOUh9Szrwl6daom0re6vHK/FWGr3fO7PvpJIQkzOXoDXKdM4H/ueEXl5y53bHQ0d/1P2DJfLOV7Lx1g+MrcaTolzgbQ7QQXlA4NL4je/zUY+qZ"
}`,
}

var flavorCols = []string{"content", "signature"}

type MockFlavorStore struct {
	Mock        sqlmock.Sqlmock
	FlavorStore *postgres.FlavorStore
}

type Flavor struct {
	ID         uuid.UUID `json:"id" gorm:"primary_key;type:uuid"`
	Content    wls.Image `json:"flavor" sql:"type:JSONB"`
	CreatedAt  time.Time `json:"created"`
	Label      string    `gorm:"unique;not null"`
	FlavorPart string    `json:"flavor_part"`
	Signature  string    `json:"signature"`
}

func (store *MockFlavorStore) RetrieveByLabel(s string) (*wls.SignedImageFlavor, error) {
	var f *wls.SignedImageFlavor
	return f, nil
}

// Create mocks flavor Create Response
func (store *MockFlavorStore) Create(f *wls.SignedImageFlavor) (*wls.SignedImageFlavor, error) {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectBegin()

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	store.Mock.ExpectQuery(`INSERT INTO "flavor" (.+)`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(newUuid.String()))

	store.Mock.ExpectCommit()

	return store.FlavorStore.Create(f)
}

// Retrieve mocks flavor Retrieve Response
func (store *MockFlavorStore) Retrieve(id uuid.UUID) (*wls.SignedImageFlavor, error) {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	// mock for returned objects
	for k, v := range flavorMap {
		var f Flavor
		err := json.Unmarshal([]byte(v), &f)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
		}
		var fContentBytes, _ = json.Marshal(&f.Content)

		store.Mock.ExpectQuery(`SELECT content, signature FROM "flavor"  WHERE  \("flavor"."id" = \$1\)`).
			WithArgs(k).
			WillReturnRows(sqlmock.NewRows(flavorCols).
				AddRow(fContentBytes, f.Signature))
	}

	store.Mock.ExpectQuery(`SELECT content, signature FROM "flavor" WHERE \("flavor"."id" = \$1\)`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27").WillReturnError(errors.New(commErr.RowsNotFound))

	return store.FlavorStore.Retrieve(id)
}

// Delete deletes flavor from the store
func (store *MockFlavorStore) Delete(flavorId uuid.UUID) error {
	// any of the options below can be applied

	store.Mock.MatchExpectationsInOrder(false)
	store.Mock.ExpectBegin()

	deleteResult := sqlmock.NewResult(1, 1)
	store.Mock.ExpectExec(`DELETE FROM "flavor"  WHERE "flavor"."id" = \$1 AND \(\("flavor"."id" = \$2\)\)`).
		WithArgs("dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f", "dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f").
		WillReturnResult(deleteResult)

	store.Mock.ExpectExec(`DELETE FROM "flavor"  WHERE "flavor"."id" = \$1 AND \(\("flavor"."id" = \$2\)\)`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27", "cf197a51-8362-465f-9ec1-d88ad0023a27").WillReturnError(errors.New(commErr.RowsNotFound))

	store.Mock.ExpectCommit()

	return store.FlavorStore.Delete(flavorId)
}

// Search returns a filtered list of flavor per the provided flavorFilterCriteria
func (store *MockFlavorStore) Search(criteria *model.FlavorFilter) ([]wls.SignedImageFlavor, error) {

	store.Mock.MatchExpectationsInOrder(false)
	//Search without filter
	allRows := sqlmock.NewRows(flavorCols)
	for _, v := range flavorMap {
		var f Flavor
		err := json.Unmarshal([]byte(v), &f)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
		}
		var fContentBytes, _ = json.Marshal(&f.Content)
		allRows.AddRow(fContentBytes, f.Signature)
	}
	store.Mock.ExpectQuery(`SELECT f.content, f.signature FROM flavor f`).
		WillReturnRows(allRows)

	// search by id, for all the rows in flavorMap
	for k, v := range flavorMap {
		var f Flavor
		err := json.Unmarshal([]byte(v), &f)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
		}
		var fContentBytes, _ = json.Marshal(&f.Content)
		store.Mock.ExpectQuery(`SELECT content, signature FROM flavor f  WHERE \(id = \$1\)`).
			WithArgs(k).
			WillReturnRows(sqlmock.NewRows(flavorCols).
				AddRow(fContentBytes, f.Signature))
	}

	var flavor1 Flavor
	_ = json.Unmarshal([]byte(flavorMap["dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f"]), &flavor1)
	var fContentBytes, _ = json.Marshal(&flavor1.Content)
	store.Mock.ExpectQuery(`SELECT content, signature FROM flavor f  WHERE \(id = \$1\)`).
		WithArgs("dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f").
		WillReturnRows(sqlmock.NewRows(flavorCols).
			AddRow(fContentBytes, flavor1.Signature))

	//When ID doesn't exist
	store.Mock.ExpectQuery(`SELECT content, signature FROM flavor f  WHERE \(id = \$1\)`).
		WithArgs("b47a13b1-0af2-47d6-91d0-717094bfda2d").
		WillReturnRows(sqlmock.NewRows(flavorCols))

	//Search by Label
	for _, v := range flavorMap {
		var f Flavor
		err := json.Unmarshal([]byte(v), &f)
		if err != nil {
			defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
		}
		var fContentBytes, _ = json.Marshal(&f.Content)

		store.Mock.ExpectQuery(`SELECT content, signature FROM flavor f  WHERE \(label = \$1\)`).
			WithArgs(f.Label).
			WillReturnRows(sqlmock.NewRows(flavorCols).
				AddRow(fContentBytes, f.Signature))
	}

	// search by label
	store.Mock.ExpectQuery(`SELECT content, signature FROM flavor f  WHERE \(label = \$1\)`).
		WithArgs("vm1-label-name").
		WillReturnRows(sqlmock.NewRows(flavorCols).
			AddRow(fContentBytes, flavor1.Signature))

	//Search by non-existing label
	store.Mock.ExpectQuery(`SELECT content, signature FROM flavor f  WHERE \(label = \$1\)`).
		WithArgs("intel").
		WillReturnRows(sqlmock.NewRows(flavorCols))

	store.Mock.ExpectQuery(`SELECT content, signature FROM flavor f  WHERE \(label = \$1\)`).
		WithArgs("12155").
		WillReturnRows(sqlmock.NewRows(flavorCols))

	return store.FlavorStore.Search(criteria)
}

// NewMockFlavorStore initializes the mock datastore
func NewMockFlavorStore() *MockFlavorStore {
	datastore, mock := postgres.NewSQLMockDataStore()

	return &MockFlavorStore{
		Mock:        mock,
		FlavorStore: postgres.NewFlavorStore(datastore),
	}
}
