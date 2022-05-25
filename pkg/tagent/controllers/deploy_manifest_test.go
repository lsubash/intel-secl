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

var _ = Describe("DeployManifest Request", func() {
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

	Describe("DeployManifest", func() {
		Context("DeployManifest request", func() {
			It("Should perform DeployManifest", func() {
				router.HandleFunc("/v2/deploy/manifest", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.DeployManifest(reqHandler), []string{"deploy_manifest:create"}))).Methods(http.MethodPost)

				manifest := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
							<Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Default_Workload_Flavor_v1.0" Uuid="7a9ac586-40f9-43b2-976b-26667431efca" DigestAlg="SHA384">
								<Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/workload-agent/bin"/>
								<Symlink Path="/opt/workload-agent/bin/wlagent"/>
								<File Path="/opt/workload-agent/bin/.*" SearchType="regex"/>
							</Manifest>`

				req, err := http.NewRequest(http.MethodPost, "/v2/deploy/manifest", strings.NewReader(manifest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_manifest:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Invalid RequestHandler in DeployManifest request", func() {
			It("Should not perform DeployManifest  - Invalid RequestHandler", func() {
				router.HandleFunc("/v2/deploy/manifest", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.DeployManifest(negReqHandler), []string{"deploy_manifest:create"}))).Methods(http.MethodPost)

				manifest := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
							<Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Default_Workload_Flavor_v1.0" Uuid="7a9ac586-40f9-43b2-976b-26667431efca" DigestAlg="SHA384">
								<Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/workload-agent/bin"/>
								<Symlink Path="/opt/workload-agent/bin/wlagent"/>
								<File Path="/opt/workload-agent/bin/.*" SearchType="regex"/>
							</Manifest>`

				req, err := http.NewRequest(http.MethodPost, "/v2/deploy/manifest", strings.NewReader(manifest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_manifest:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Invalid Request Body in DeployManifest request", func() {
			It("Should not perform DeployManifest - Invalid Request Body", func() {
				router.HandleFunc("/v2/deploy/manifest", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.DeployManifest(reqHandler), []string{"deploy_manifest:create"}))).Methods(http.MethodPost)

				manifest := ``

				req, err := http.NewRequest(http.MethodPost, "/v2/deploy/manifest", strings.NewReader(manifest))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_manifest:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Invalid Content-Type in DeployManifest request", func() {
			It("Should not perform DeployManifest - Invalid Content-Type", func() {
				router.HandleFunc("/v2/binding-key-certificate", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.DeployManifest(reqHandler), []string{"deploy_manifest:create"}))).Methods(http.MethodPost)

				req, err := http.NewRequest(http.MethodPost, "/v2/binding-key-certificate", nil)
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"deploy_manifest:create"},
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
