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
	"strings"
)

var _ = Describe("SetAssetTag Request", func() {
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

	Describe("SetAssetTag", func() {
		Context("SetAssetTag request", func() {
			It("Should perform SetAssetTag", func() {
				router.HandleFunc("/v2/tag", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.SetAssetTag(reqHandler), []string{"deploy_tag:create"}))).Methods(http.MethodPost)
				tagRequest := `{
					 "tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
					 "hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/tag", strings.NewReader(tagRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_tag:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Invalid RequestHandler in SetAssetTag request", func() {
			It("Should not perform SetAssetTag - Invalid RequestHandler", func() {
				router.HandleFunc("/v2/tag", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.SetAssetTag(negReqHandler), []string{"deploy_tag:create"}))).Methods(http.MethodPost)
				tagRequest := `{
					 "tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
					 "hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/tag", strings.NewReader(tagRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_tag:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Invalid Content-Type in SetAssetTag request", func() {
			It("Should not perform SetAssetTag - Invalid Content-Type", func() {
				router.HandleFunc("/v2/tag", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.SetAssetTag(reqHandler), []string{"deploy_tag:create"}))).Methods(http.MethodPost)
				tagRequest := `{
					 "tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
					 "hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/tag", strings.NewReader(tagRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_tag:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", "")
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Invalid Request Body in SetAssetTag request", func() {
			It("Should not perform SetAssetTag - Invalid Request Body", func() {
				router.HandleFunc("/v2/tag", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.SetAssetTag(negReqHandler), []string{"deploy_tag:create"}))).Methods(http.MethodPost)
				tagRequest := `{
					 "tag             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
					 "hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262
				 }`

				req, err := http.NewRequest(http.MethodPost, "/v2/tag", strings.NewReader(tagRequest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_tag:create"},
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
