/*
Copyright © 2019 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/isecl-k8s-extensions/isecl-k8s-scheduler/controllers"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtendedScheduler(t *testing.T) {
	fmt.Println("Starting extended scheduler Test...")
	gin.SetMode(gin.TestMode)

	testrouter := mux.NewRouter()
	apiInst := controllers.FilterHandler{}
	testrouter.HandleFunc("/", controllers.VersionController{}.GetVersion).Methods(http.MethodGet)
	testrouter.HandleFunc(constants.FilterEndpoint, apiInst.Filter).Methods(http.MethodPost)

	// test POST /filter with empty body
	req, err := http.NewRequest(http.MethodPost, constants.FilterEndpoint, nil)
	if err != nil {
		fmt.Println(err)
	}

	resp := httptest.NewRecorder()
	testrouter.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("Expecting status 404 not found : got : %v", resp.Code)
	}

	// test POST /filter with valid body
	req, err = http.NewRequest(http.MethodPost, constants.FilterEndpoint, nil)
	if err != nil {
		fmt.Println(err)
	}

	resp = httptest.NewRecorder()
	testrouter.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("Expecting status 200 not found : got : %v", resp.Code)
	}

	// test POST /filter with valid body
	req, err = http.NewRequest(http.MethodPost, constants.FilterEndpoint, nil)
	if err != nil {
		fmt.Println(err)
	}

	resp = httptest.NewRecorder()
	testrouter.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("Expecting status 200 not found : got : %v", resp.Code)
	}

	// test GET / with valid body
	req, err = http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		fmt.Println(err)
	}

	resp = httptest.NewRecorder()
	testrouter.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("Expecting status 200 found : got : %v", resp.Code)
	}
}
