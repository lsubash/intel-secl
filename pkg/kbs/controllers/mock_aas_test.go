/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"net/http"

	aasTypes "github.com/intel-secl/intel-secl/v5/pkg/authservice/types"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/aas"
	types "github.com/intel-secl/intel-secl/v5/pkg/model/aas"
)

func NewMockAASClient(aasURL string, token []byte, client aas.HttpClient) aas.AASClient {
	return &MockAasClient{
		BaseURL:    aasURL,
		JWTToken:   token,
		HTTPClient: client,
	}
}

type MockAasClient struct {
	BaseURL    string
	JWTToken   []byte
	HTTPClient aas.HttpClient
}

func (c *MockAasClient) PrepReqHeader(req *http.Request) {
}

func (c *MockAasClient) CreateUser(u types.UserCreate) (*types.UserCreateResponse, error) {
	return nil, nil
}

func (c *MockAasClient) GetUsers(name string) ([]types.UserCreateResponse, error) {
	return nil, nil
}

func (c *MockAasClient) CreateRole(r types.RoleCreate) (*types.RoleCreateResponse, error) {
	return nil, nil
}

func (c *MockAasClient) AddRoleToUser(userID string, r types.RoleIDs) error {
	return nil
}

func (c *MockAasClient) GetRoles(service, name, context, contextContains string, allContexts bool) (aasTypes.Roles, error) {
	return nil, nil
}

func (c *MockAasClient) DeleteRole(roleId string) error {
	return nil
}

func (c *MockAasClient) GetPermissionsForUser(userID string) ([]types.PermissionInfo, error) {
	return nil, nil
}

func (c *MockAasClient) GetRolesForUser(userID string) ([]types.RoleInfo, error) {
	return nil, nil
}

func (c *MockAasClient) UpdateUser(userID string, user types.UserCreate) error {
	return nil
}

func (c *MockAasClient) GetCredentials(createCredentailsReq types.CreateCredentialsReq) ([]byte, error) {
	return nil, nil
}

func (c *MockAasClient) GetCustomClaimsToken(customClaimsTokenReq types.CustomClaims) ([]byte, error) {
	return nil, nil
}

func (c *MockAasClient) GetJwtSigningCertificate() ([]byte, error) {
	return jwtsigncert, nil
}
