/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain/mocks"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v5/pkg/wls/domain/mocks"
	wlsRoutes "github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("ImageController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var imageStore *mocks2.MockImageStore
	var flavorStore *mocks2.MockFlavorStore
	var imageController *controllers.ImageController
	BeforeEach(func() {
		router = mux.NewRouter()
		imageStore = mocks2.NewMockImageStore()
		flavorStore = mocks2.NewMockFlavorStore()
		var conf config.Configuration
		certStore := mocks.NewFakeCertificatesStore()
		imageController = controllers.NewImageController(imageStore, flavorStore, &conf, certStore)
	})

	//GetAllAssociatedFlavors
	Describe("Retrieve all the flavors Associated with Image ID", func() {
		Context("A valid image ID is provided", func() {
			It("Should Retrieve all the associated Flavor and return a 200 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAllAssociatedFlavorsv1))).Methods("GET")
				req, err := http.NewRequest("GET", "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("When non-existing image ID is provided", func() {
			It("Should Not Retrieve associated Flavor and return a 404 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAllAssociatedFlavorsv1))).Methods("GET")
				req, err := http.NewRequest("GET", "/images/1d61f86c-c522-4506-a3a0-a97e85c8d33e/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("When wrong format image id is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAllAssociatedFlavorsv1))).Methods("GET")
				req, err := http.NewRequest("GET", "/images/xd61f86c-c522-4506-a3a0-a97e85c8d33/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	//GetAllAssociatedFlavor
	Describe("Retrieve the complete flavor Associated with Image ID", func() {
		Context("A valid image ID and flavor id is provided", func() {
			It("Should associated Flavor and return a 200 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavorv1))).Methods("GET")
				req, err := http.NewRequest("GET", "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/9541a9f0-b427-4a0a-8e25-12f50edd3e66", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Non existing flavor id is provided", func() {
			It("Should not Retrieve Flavor and return a 404 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavorv1))).Methods("GET")
				req, err := http.NewRequest("GET", "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/1d61f86c-c522-4506-a3a0-a97e85c8d33e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Wrong format flavor ID is passed", func() {
			It("Should not Retrieve Flavor and return a 400 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavorv1))).Methods("GET")
				req, err := http.NewRequest("GET", "/images/xfff021e-9669-4e53-9224-8880fb4e408/flavors/1d61f86c-c522-4506-a3a0-a97e85c8d33e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Wrong format image ID is passed", func() {
			It("Should not Retrieve Flavor and return a 400 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavorv1))).Methods("GET")
				req, err := http.NewRequest("GET", "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/xd61f86c-c522-4506-a3a0-a97e85c8d3e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

})
