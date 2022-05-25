/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aps"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// MockKeyTransferPolicyStore provides a mocked implementation of interface domain.KeyTransferPolicyStore
type MockKeyTransferPolicyStore struct {
	KeyTransferPolicyStore map[uuid.UUID]*kbs.KeyTransferPolicy
}

// Create inserts a KeyTransferPolicy into the store
func (store *MockKeyTransferPolicyStore) Create(p *kbs.KeyTransferPolicy) (*kbs.KeyTransferPolicy, error) {
	store.KeyTransferPolicyStore[p.ID] = p
	return p, nil
}

// Retrieve returns a single KeyTransferPolicy record from the store
func (store *MockKeyTransferPolicyStore) Retrieve(id uuid.UUID) (*kbs.KeyTransferPolicy, error) {
	if p, ok := store.KeyTransferPolicyStore[id]; ok {
		return p, nil
	}
	return nil, errors.New(commErr.RecordNotFound)
}

// Update KeyTransferPolicy record in the store
func (store *MockKeyTransferPolicyStore) Update(policy *kbs.KeyTransferPolicy) (*kbs.KeyTransferPolicy, error) {
	if p, ok := store.KeyTransferPolicyStore[policy.ID]; ok {
		store.KeyTransferPolicyStore[p.ID] = policy
		return p, nil
	}
	return nil, errors.New(commErr.RecordNotFound)
}

// Delete deletes KeyTransferPolicy from the store
func (store *MockKeyTransferPolicyStore) Delete(id uuid.UUID) error {
	if _, ok := store.KeyTransferPolicyStore[id]; ok {
		delete(store.KeyTransferPolicyStore, id)
		return nil
	}
	return errors.New(commErr.RecordNotFound)
}

// Search returns a filtered list of KeyTransferPolicies per the provided KeyTransferPolicyFilterCriteria
func (store *MockKeyTransferPolicyStore) Search(criteria *models.KeyTransferPolicyFilterCriteria) ([]kbs.KeyTransferPolicy, error) {

	var policies []kbs.KeyTransferPolicy
	// start with all records
	for _, p := range store.KeyTransferPolicyStore {
		policies = append(policies, *p)
	}

	// KeyTransferPolicy filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, models.KeyTransferPolicyFilterCriteria{}) {
		return policies, nil
	}

	return policies, nil
}

// NewFakeKeyTransferPolicyStore loads dummy data into MockKeyTransferPolicyStore
func NewFakeKeyTransferPolicyStore() *MockKeyTransferPolicyStore {
	store := &MockKeyTransferPolicyStore{}
	store.KeyTransferPolicyStore = make(map[uuid.UUID]*kbs.KeyTransferPolicy)

	var i uint16 = 0
	_, err := store.Create(&kbs.KeyTransferPolicy{
		ID:              uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		AttestationType: []aps.AttestationType{aps.SGX},
		SGX: &kbs.SgxPolicy{
			Attributes: &kbs.SgxAttributes{
				MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
				IsvProductId:       []uint16{1},
				MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
				IsvSvn:             &i,
				ClientPermissions:  []string{"nginx", "USA"},
				EnforceTCBUptoDate: nil,
			},
		},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer policy")
	}

	_, err = store.Create(&kbs.KeyTransferPolicy{
		ID:              uuid.MustParse("73755fda-c910-46be-821f-e8ddeab189e9"),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		AttestationType: []aps.AttestationType{aps.SGX},
		SGX: &kbs.SgxPolicy{
			Attributes: &kbs.SgxAttributes{
				MrSigner:           []string{"cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"},
				IsvProductId:       []uint16{1},
				MrEnclave:          []string{"01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"},
				IsvSvn:             &i,
				ClientPermissions:  []string{"nginx", "USA"},
				EnforceTCBUptoDate: nil,
			},
		},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer policy")
	}

	var j uint8 = 0

	_, err = store.Create(&kbs.KeyTransferPolicy{
		ID:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		CreatedAt:       time.Now().UTC(),
		AttestationType: []aps.AttestationType{aps.TDX},
		TDX: &kbs.TdxPolicy{
			Attributes: &kbs.TdxAttributes{
				MrSignerSeam:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
				MrSeam:             []string{"0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"},
				SeamSvn:            &j,
				MRTD:               []string{"cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"},
				RTMR0:              "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
				RTMR1:              "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
				RTMR2:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				RTMR3:              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				EnforceTCBUptoDate: nil,
			},
		},
	})
	if err != nil {
		log.WithError(err).Errorf("Error creating key transfer policy")
	}
	return store
}
