/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"strings"

	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/context"
	ct "github.com/intel-secl/intel-secl/v5/pkg/model/aas"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/common"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/config"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/tagent/controllers"
	tagentRouter "github.com/intel-secl/intel-secl/v5/pkg/tagent/router"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
)

const (
	reprovisionFilePath = "../test/resources/etc/trustagent/reprovision-file-list.txt"
)

var _ = Describe("ReprovisionImaPolicy Request", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	// Read Config
	testCfg, err := os.ReadFile(testConfig)
	if err != nil {
		log.Fatalf("Failed to load test tagent config file %v", err)
	}
	var tagentConfig *config.TrustAgentConfiguration
	yaml.Unmarshal(testCfg, &tagentConfig)

	testConfig_test, err := os.ReadFile(testConfig_test)
	if err != nil {
		log.Fatalf("Failed to load test tagent config file %v", err)
	}
	var testConfig *config.TrustAgentConfiguration
	yaml.Unmarshal(testConfig_test, &testConfig)

	var reqHandler common.RequestHandler
	var negReqHandler common.RequestHandler

	BeforeEach(func() {
		router = mux.NewRouter()
		reqHandler = common.NewMockRequestHandler(tagentConfig)
		negReqHandler = common.NewMockRequestHandler(testConfig)
	})

	// Specs for HTTP Post to "/v2/host/reprovision-ima"
	Describe("ReprovisionImaPolicy request to append new files and folder measurements in imalog", func() {
		Context("ReprovisionImaPolicy request", func() {
			It("Should perform ReprovisionImaPolicy", func() {
				router.HandleFunc("/v2/host/reprovision-ima", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.ReprovisionImaPolicy(reqHandler), []string{"reprovision_ima:update"}))).Methods(http.MethodPost)
				reprovisionRequest := `{
					"files"             : ["file1", "file2"]
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/host/reprovision-ima", strings.NewReader(reprovisionRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"reprovision_ima:update"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Invalid RequestHandler in ReprovisionImaPolicy request", func() {
			It("Should not perform ReprovisionImaPolicy - Invalid RequestHandler", func() {
				router.HandleFunc("/v2/host/reprovision-ima", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.ReprovisionImaPolicy(negReqHandler), []string{"reprovision_ima:update"}))).Methods(http.MethodPost)
				reprovisionRequest := `{
					"files"             : ["file1", "file2"]
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/host/reprovision-ima", strings.NewReader(reprovisionRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"reprovision_ima:update"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Invalid Content-Type in ReprovisionImaPolicy request", func() {
			It("Should not perform ReprovisionImaPolicy - Invalid Content-Type", func() {
				router.HandleFunc("/v2/host/reprovision-ima", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.ReprovisionImaPolicy(reqHandler), []string{"reprovision_ima:update"}))).Methods(http.MethodPost)
				reprovisionRequest := `{
					"files"             : ["file1", "file2"]
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/host/reprovision-ima", strings.NewReader(reprovisionRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"reprovision_ima:update"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", "")
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Invalid Request Body in ReprovisionImaPolicy request", func() {
			It("Should not perform ReprovisionImaPolicy - Invalid Request Body", func() {
				router.HandleFunc("/v2/host/reprovision-ima", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.ReprovisionImaPolicy(reqHandler), []string{"reprovision_ima:update"}))).Methods(http.MethodPost)
				reprovisionRequest := `{
					"files"             : "file1"
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/host/reprovision-ima", strings.NewReader(reprovisionRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"reprovision_ima:update"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
