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
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/postgres"
	"github.com/pkg/errors"
	"time"
)

var imageFlavorCols = []string{"image_id", "flavor_id"}
var SignedImageFlavorCols = []string{"flavor", "signature"}
var flavorIDCol = []string{"id"}
var flavorAllCols = []string{"id", "created_at", "label", "flavor_part", "flavor", "signature"}

var imageMap = map[string]string{
	"ffff021e-9669-4e53-9224-8880fb4e4081": `{
    "id": "ffff021e-9669-4e53-9224-8880fb4e4081",
    "flavor_ids": [
        "9541a9f0-b427-4a0a-8e25-12f50edd3e66"
    ] 
}`,
}

var flavorsMap = map[string]string{
	"9541a9f0-b427-4a0a-8e25-12f50edd3e66": `{"id": "9541a9f0-b427-4a0a-8e25-12f50edd3e66",
"created": "` + time.Now().Format(time.RFC3339) + `",
"label": "vm1-label-name",
"flavor_part": "IMAGE",
"flavor": {
    "meta": {
        "id": "9541a9f0-b427-4a0a-8e25-12f50edd3e66",
        "description": {
            "label": "vm1-label-name",
            "flavor_part": "IMAGE"
        }
    },
    "integrity": {},
    "encryption": {
        "key_url": "http://localhost:1337/v1/keys/eb61b2e9-c7cd-4476-ac5f-71582c892112/transfer"
    },
    "integrity_enforced": false,
    "encryption_required": true
},
"signature": "N6J8yVIW5XT2KCudY2ShL7MlR2vffOg/olf/QFJKEiu5qAQri254G9LSkQ53CX3KrHQdNXpZdEcYfhunEnzIS3IOuihACCIBeN1Wz0ly0aWEraV21/e1kVeTOFuG8CJQqli00a1XkMFpn2Ik6NNbnwHQ/wUohxqjQ8MRunMP/Aj2rtWmZqDowL9ZjLpvS6Lk/AmfkPq/ai8zdv4uhoaIZZBs9SGQUPWiejhMeHNdjoP+t/D5SCuRJ7bsMBmw9F5ctUwgwS9gy9ThDUUhevQmoBpdFybkc+CU2xO0U/J+alqPO54nytPOLy7aU99SSD68N30jYkYdm+0ORXSMRk3raKcf9zAO8M3hWqctaKsfnMAJTaLvOzo7zNrIf1zoEfIAjJYWgjWUSgtzh5t0sPQOUh9Szrwl6daom0re6vHK/FWGr3fO7PvpJIQkzOXoDXKdM4H/ueEXl5y53bHQ0d/1P2DJfLOV7Lx1g+MrcaTolzgbQ7QQXlA4NL4je/zUY+qZ"
}`,
}

type MockImageStore struct {
	Mock       sqlmock.Sqlmock
	ImageStore *postgres.ImageStore
}

func (store *MockImageStore) Create(image *model.Image) error {

	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectBegin()

	var f Flavor
	err := json.Unmarshal([]byte(flavorMap["9541a9f0-b427-4a0a-8e25-12f50edd3e66"]), &f)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}
	var fContentBytes, _ = json.Marshal(&f.Content)

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id in \(\$2\)\)\) ORDER BY "image_flavor"."image_id" ASC LIMIT 1`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols))

	store.Mock.ExpectQuery(`SELECT \* FROM "flavor" (.+)`).
		WithArgs("9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows(flavorAllCols).
			AddRow(f.ID, f.CreatedAt, f.Label, f.FlavorPart, fContentBytes, f.Signature))

	store.Mock.ExpectQuery(`SELECT \* FROM "flavor" (.+)`).
		WithArgs("3d41c64f-ee70-4cbf-bdde-a03835a21625").
		WillReturnRows(sqlmock.NewRows(flavorAllCols))

	var imgf model.Image
	err = json.Unmarshal([]byte(imageMap["ffff021e-9669-4e53-9224-8880fb4e4081"]), &imgf)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}

	var id, _ = json.Marshal(&imgf.ID)

	store.Mock.ExpectQuery(`INSERT INTO "image_flavor" (.+)`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow(id))

	store.Mock.ExpectCommit()

	return store.ImageStore.Create(image)
}

func (store MockImageStore) Delete(uuid uuid.UUID) error {

	store.Mock.MatchExpectationsInOrder(false)
	store.Mock.ExpectBegin()

	deleteResult := sqlmock.NewResult(1, 1)
	store.Mock.ExpectExec(`DELETE FROM "image_flavor" WHERE "image_flavor"."image_id" = \$1`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnResult(deleteResult)

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id = \$2\)\) ORDER BY "image_flavor"."image_id" ASC LIMIT 1`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id = \$2\)\) ORDER BY "image_flavor"."image_id" ASC LIMIT 1`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27", "cf197a51-8362-465f-9ec1-d88ad0023a27").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols))

	store.Mock.ExpectExec(`DELETE FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27").WillReturnError(errors.New(commErr.RowsNotFound))

	store.Mock.ExpectCommit()
	return store.ImageStore.Delete(uuid)
}

func (store MockImageStore) DeleteImageFlavorAssociation(imageUUID uuid.UUID, flavorUUID uuid.UUID) error {
	store.Mock.MatchExpectationsInOrder(false)
	store.Mock.ExpectBegin()

	deleteResult := sqlmock.NewResult(1, 1)
	store.Mock.ExpectExec(`DELETE FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id = \$2 and flavor_id=\$3 \)\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "ffff021e-9669-4e53-9224-8880fb4e4081", "58967607-6292-4d53-815c-5efbd1fc8818").
		WillReturnResult(deleteResult)

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id = \$2 and flavor_id = \$3\)\) ORDER BY "image_flavor"."image_id" ASC LIMIT 1`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "ffff021e-9669-4e53-9224-8880fb4e4081", "58967607-6292-4d53-815c-5efbd1fc8818").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id = \$2 and flavor_id = \$3\)\) ORDER BY "image_flavor"."image_id" ASC LIMIT 1`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "ffff021e-9669-4e53-9224-8880fb4e4081", "dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols))

	store.Mock.ExpectExec(`DELETE FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id = \$2 and flavor_id=\$3 \)\)`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27", "cf197a51-8362-465f-9ec1-d88ad0023a27", "f4580654-8eb8-4412-966b-ffba017901bd").WillReturnError(errors.New(commErr.RowsNotFound))

	store.Mock.ExpectCommit()

	return store.ImageStore.DeleteImageFlavorAssociation(imageUUID, flavorUUID)
}

func (store MockImageStore) Retrieve(uuid uuid.UUID) (*model.Image, error) {

	store.Mock.MatchExpectationsInOrder(false)

	var imgf wls.ImageFlavor
	err := json.Unmarshal([]byte(imageMap["ffff021e-9669-4e53-9224-8880fb4e4081"]), &imgf)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081").WillReturnRows(sqlmock.NewRows(imageFlavorCols).
		AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1\)`).
		WithArgs("b3096138-692d-48fe-b386-81a9d67c085d").WillReturnError(errors.New(commErr.RowsNotFound))

	return store.ImageStore.Retrieve(uuid)
}

func (store MockImageStore) RetrieveAssociatedFlavorByFlavorPart(imageUUID uuid.UUID, flavorPart string) (*wls.SignedImageFlavor, error) {
	store.Mock.MatchExpectationsInOrder(false)

	var f Flavor
	err := json.Unmarshal([]byte(flavorMap["9541a9f0-b427-4a0a-8e25-12f50edd3e66"]), &f)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}
	var fContentBytes, _ = json.Marshal(&f.Content)

	store.Mock.ExpectQuery(`SELECT flavor.content,flavor.signature FROM "flavor" INNER JOIN image_flavor imgf ON flavor.id = imgf.flavor_id WHERE \(imgf.image_id=\$1 AND flavor.flavor_part=\$2\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "IMAGE").
		WillReturnRows(sqlmock.NewRows(SignedImageFlavorCols).
			AddRow(fContentBytes, f.Signature))

	store.Mock.ExpectQuery(`SELECT flavor.content,flavor.signature FROM "flavor" INNER JOIN image_flavor imgf ON flavor.id = imgf.flavor_id WHERE \(imgf.image_id=\$1 AND flavor.flavor_part=\$2\)`).
		WithArgs("b3096138-692d-48fe-b386-81a9d67c085d", "IMAGE").
		WillReturnError(errors.New(commErr.RowsNotFound))

	store.Mock.ExpectQuery(`SELECT flavor.content,flavor.signature FROM "flavor" INNER JOIN image_flavor imgf ON flavor.id = imgf.flavor_id WHERE \(imgf.image_id=\$1 AND flavor.flavor_part=\$2\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "xjyzg").
		WillReturnRows(sqlmock.NewRows(SignedImageFlavorCols))

	return store.ImageStore.RetrieveAssociatedFlavorByFlavorPart(imageUUID, flavorPart)
}

//update select, but cant have controller, as it needs kBS key
func (store MockImageStore) RetrieveImageFlavor(imageUUID uuid.UUID) (*wls.SignedImageFlavor, error) {
	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.MatchExpectationsInOrder(false)
	var f Flavor
	err := json.Unmarshal([]byte(flavorsMap["9541a9f0-b427-4a0a-8e25-12f50edd3e66"]), &f)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}
	var fContentBytes, _ = json.Marshal(&f.Content)

	store.Mock.ExpectQuery(`SELECT flavor.content,flavor.signature FROM "flavor" INNER JOIN image_flavor imgf ON flavor.id = imgf.flavor_id WHERE \(imgf.image_id=\$1 AND \(flavor.flavor_part=\$2 OR flavor.flavor_part=\$3\)\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "IMAGE", "CONTAINER_IMAGE").
		WillReturnRows(sqlmock.NewRows(SignedImageFlavorCols).
			AddRow(fContentBytes, f.Signature))

	store.Mock.ExpectQuery(`SELECT flavor.content,flavor.signature FROM "flavor" INNER JOIN image_flavor imgf ON flavor.id = imgf.flavor_id WHERE \(imgf.image_id=\$1 AND \(flavor.flavor_part=\$2 OR flavor.flavor_part=\$3\)\)`).
		WithArgs("1d61f86c-c522-4506-a3a0-a97e85c8d33e", "IMAGE", "CONTAINER_IMAGE").
		WillReturnError(errors.New(commErr.RowsNotFound))
	return store.ImageStore.RetrieveImageFlavor(imageUUID)
}

func (store MockImageStore) Search(filter model.ImageFilter) ([]*model.ImageFilter, error) {

	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectQuery(`SELECT \* FROM \"image_flavor\"  WHERE \(image_id = \$1\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).
			AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM \"image_flavor\"  WHERE \(image_id = \$1\) AND \(flavor_id = \$2\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).
			AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM \"image_flavor\"  WHERE \(flavor_id = \$1\)`).
		WithArgs("9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).
			AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM \"image_flavor\"  WHERE \(image_id = \$1\)`).
		WithArgs("1d61f86c-c522-4506-a3a0-a97e85c8d33e").WillReturnRows(sqlmock.NewRows(imageFlavorCols))

	return store.ImageStore.Search(filter)
}

func (store MockImageStore) Update(imageUUID uuid.UUID, flavorUUID uuid.UUID) error {

	store.Mock.MatchExpectationsInOrder(false)
	store.Mock.ExpectBegin()

	var f Flavor
	err := json.Unmarshal([]byte(flavorMap["9541a9f0-b427-4a0a-8e25-12f50edd3e66"]), &f)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}
	var fContentBytes, _ = json.Marshal(&f.Content)

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE "image_flavor"."image_id" = \$1 AND \(\(image_id = \$2\)\) ORDER BY "image_flavor"."image_id" ASC LIMIT 1`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "3d41c64f-ee70-4cbf-bdde-a03835a21625"))

	store.Mock.ExpectQuery(`SELECT \* FROM "flavor"  WHERE "flavor"."id" = \$1 AND \(\(id = \$2\)\) ORDER BY "flavor"."id" ASC LIMIT 1`).
		WithArgs("3d41c64f-ee70-4cbf-bdde-a03835a21625", "3d41c64f-ee70-4cbf-bdde-a03835a21625").
		WillReturnRows(sqlmock.NewRows(flavorAllCols).AddRow(f.ID, f.CreatedAt, f.Label, f.FlavorPart, fContentBytes, f.Signature))

	store.Mock.ExpectExec(`UPDATE "image_flavor" SET "flavor_id" = \$1  WHERE \(image_id=\$2\)`).
		WithArgs("3d41c64f-ee70-4cbf-bdde-a03835a21625", "ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnResult(sqlmock.NewResult(0, 1))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1 and flavor_id=\$2\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1 and flavor_id=\$2\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "3d41c64f-ee70-4cbf-bdde-a03835a21625").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols))

	store.Mock.ExpectQuery(`SELECT \* FROM \"image_flavor\"  WHERE \(image_id = \$1\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081").WillReturnRows(sqlmock.NewRows(imageFlavorCols))

	store.Mock.ExpectQuery(`SELECT \* FROM "flavor" (.+))`).
		WillReturnRows(sqlmock.NewRows(flavorAllCols).
			AddRow(f.ID, f.CreatedAt, f.Label, f.FlavorPart, fContentBytes, f.Signature))

	store.Mock.ExpectQuery(`INSERT INTO "image_flavor" (.+)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow("ffff021e-9669-4e53-9224-8880fb4e4081"))

	store.Mock.ExpectCommit()

	return store.ImageStore.Update(imageUUID, flavorUUID)
}

func (store MockImageStore) RetrieveFlavors(uuid uuid.UUID) (*model.Image, error) {

	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).
			AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1\)`).
		WithArgs("1d61f86c-c522-4506-a3a0-a97e85c8d33e").WillReturnError(errors.New(commErr.RowsNotFound))

	return store.ImageStore.RetrieveFlavors(uuid)
}

func (store MockImageStore) RetrieveFlavor(imageUUID uuid.UUID, flavorUUID uuid.UUID) (*model.Image, error) {

	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1 and flavor_id = \$2\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).
			AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1 and flavor_id = \$2\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081", "1d61f86c-c522-4506-a3a0-a97e85c8d33e").WillReturnError(errors.New(commErr.RowsNotFound))

	return store.ImageStore.RetrieveFlavor(imageUUID, flavorUUID)
}

func (store MockImageStore) RetrieveFlavorV1(imageUUID uuid.UUID, flavorUUID uuid.UUID) (*wls.SignedImageFlavor, error) {
	store.Mock.MatchExpectationsInOrder(false)
	var f Flavor
	err := json.Unmarshal([]byte(flavorMap["9541a9f0-b427-4a0a-8e25-12f50edd3e66"]), &f)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}
	var fContentBytes, _ = json.Marshal(&f.Content)

	store.Mock.ExpectQuery(`SELECT content,signature FROM "flavor"  WHERE \(id=\$1\)`).
		WithArgs("9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows(SignedImageFlavorCols).
			AddRow(fContentBytes, f.Signature))

	store.Mock.ExpectQuery(`SELECT content,signature FROM "flavor"  WHERE \(id=\$1\)`).
		WithArgs("1d61f86c-c522-4506-a3a0-a97e85c8d33e").
		WillReturnError(errors.New(commErr.RowsNotFound))

	return store.ImageStore.RetrieveFlavorV1(imageUUID, flavorUUID)
}

func (store MockImageStore) RetrieveFlavorsV1(uuid uuid.UUID) ([]wls.SignedImageFlavor, error) {
	store.Mock.MatchExpectationsInOrder(false)
	var f Flavor
	err := json.Unmarshal([]byte(flavorMap["9541a9f0-b427-4a0a-8e25-12f50edd3e66"]), &f)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating unmarshalling data")
	}
	var fContentBytes, _ = json.Marshal(&f.Content)

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1\)`).
		WithArgs("ffff021e-9669-4e53-9224-8880fb4e4081").
		WillReturnRows(sqlmock.NewRows(imageFlavorCols).
			AddRow("ffff021e-9669-4e53-9224-8880fb4e4081", "9541a9f0-b427-4a0a-8e25-12f50edd3e66"))

	store.Mock.ExpectQuery(`SELECT \* FROM "image_flavor"  WHERE \(image_id = \$1\)`).
		WithArgs("1d61f86c-c522-4506-a3a0-a97e85c8d33e").
		WillReturnError(errors.New(commErr.RowsNotFound))

	store.Mock.ExpectQuery(`SELECT content,signature FROM "flavor"  WHERE \(id=\$1\)`).
		WithArgs("9541a9f0-b427-4a0a-8e25-12f50edd3e66").
		WillReturnRows(sqlmock.NewRows(SignedImageFlavorCols).
			AddRow(fContentBytes, f.Signature))
	return store.ImageStore.RetrieveFlavorsV1(uuid)
}

// NewMockTagCertificateStore initializes the mock datastore
func NewMockImageStore() *MockImageStore {
	datastore, mock := postgres.NewSQLMockDataStore()
	return &MockImageStore{
		Mock:       mock,
		ImageStore: postgres.NewImageStore(datastore),
	}
}
