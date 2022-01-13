/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v5/pkg/wls/domain/mocks"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	wlsRoutes "github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	"strings"
)

var _ = Describe("FlavorController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorStore *mocks2.MockFlavorStore
	var flavorController *controllers.FlavorController

	BeforeEach(func() {
		router = mux.NewRouter()
		flavorStore = mocks2.NewMockFlavorStore()
		flavorController = controllers.NewFlavorController(flavorStore)
	})

	Describe("Create Flavor", func() {

		Context("When a empty Flavor Create Request is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")
				// Create Request body
				createfReq := ``

				req, err := http.NewRequest(
					"POST",
					"/flavors",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When a VALID Flavor Create Request is passed which already exist in database", func() {
			It("A new Flavor record is created and HTTP Status: 409 response is received", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")

				createfReq := `{
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
}`
				req, err := http.NewRequest(
					"POST",
					"/flavors",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusConflict))
			})
		})

		Context("When an invalid Content-Type is set", func() {
			It("Should return 415: StatusUnsupportedMediaType response is received", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")

				createfReq := ``

				req, err := http.NewRequest(
					"POST",
					"/flavors",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("When an invalid flavor content is set", func() {
			It("Should return 400 response is received", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Create))).Methods("POST")

				createfReq := `"flavor": {
    "meta": {
        "id": "dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f",
        "description": {
            "label": "vm1-label-name",
            "flavor_part": "IMAGE"
        }
    },
    "integrity_enforced": false,
    "encryption_required": true
},
"signature": "N6J8yVIW5XT2KCudY2ShL7MlR2vffOg/olf/QFJKEiu5qAQri254G9LSkQ53CX3KrHQdNXpZdEcYfhunEnzIS3IOuihACCIBeN1Wz0ly0aWEraV21/e1kVeTOFuG8CJQqli00a1XkMFpn2Ik6NNbnwHQ/wUohxqjQ8MRunMP/Aj2rtWmZqDowL9ZjLpvS6Lk/AmfkPq/ai8zdv4uhoaIZZBs9SGQUPWiejhMeHNdjoP+t/D5SCuRJ7bsMBmw9F5ctUwgwS9gy9ThDUUhevQmoBpdFybkc+CU2xO0U/J+alqPO54nytPOLy7aU99SSD68N30jYkYdm+0ORXSMRk3raKcf9zAO8M3hWqctaKsfnMAJTaLvOzo7zNrIf1zoEfIAjJYWgjWUSgtzh5t0sPQOUh9Szrwl6daom0re6vHK/FWGr3fO7PvpJIQkzOXoDXKdM4H/ueEXl5y53bHQ0d/1P2DJfLOV7Lx1g+MrcaTolzgbQ7QQXlA4NL4je/zUY+qZ"
}`

				req, err := http.NewRequest(
					"POST",
					"/flavors",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})
	// Specs for HTTP Get to "/flavors"
	Describe("Search Flavor", func() {
		Context("When no arguments are passed", func() {
			It("At least one parameter is required and a 400 response code", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by Flavor id", func() {
			It("Should get a single Flavor entry and a 200 response code", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors?id=dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var fCollection *model.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &fCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(fCollection.Flavors)).To(Equal(1))
			})
		})

		Context("When filtered by Invalid Flavor uuid", func() {
			It("Should not get the Flavor entry and a 400 response code", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors?id=za22f83-b6dd-4bf3-9b07-ff1fa01eb69f", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by Flavor id which doesn't exist", func() {
			It("Should get an empty list of Flavor entry and a 200 response code", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors?id=b47a13b1-0af2-47d6-91d0-717094bfda2d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var fCollection *model.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &fCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(fCollection.Flavors)).To(Equal(0))
			})
		})

		Context("When filtered by label", func() {
			It("Should get a Flavor entry and a 200 response code", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors?label=vm1-label-name", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var fCollection *model.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &fCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(fCollection.Flavors)).To(Equal(1))
			})
		})

		Context("When an non existing label string is provided", func() {
			It("Should return 200", func() {
				router.Handle("/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors?label=12155", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})
	// Specs for HTTP DELETE to "/flavor/{flavor_id}"
	Describe("Delete Flavor by ID", func() {

		Context("Delete Flavor by ID from data store", func() {
			It("Should delete Flavor and return a 204 response code", func() {
				router.Handle("/flavors/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(flavorController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavors/dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("Delete Flavor by incorrect ID from data store", func() {
			It("Should fail to delete Flavor and return a 404 response code", func() {
				router.Handle("/flavors/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(flavorController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavors/cf197a51-8362-465f-9ec1-d88ad0023a27", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Internal Server error request", func() {
			It("Should fail to delete Flavor and return a 500 response code", func() {
				router.Handle("/flavors/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(flavorController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavors/1d61f86c-c522-4506-a3a0-a97e85c8d33e", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	// Specs for HTTP Retrieve to "/flavor/{flavor_id}"
	Describe("Retrieve Flavor by ID", func() {
		Context("Retrieve Flavor by ID from data store", func() {
			It("Should Retrieve Flavor and return a 200 response code", func() {
				router.Handle("/flavors/{id}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors/dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve Flavor by incorrect ID from data store", func() {
			It("Should fail to Retrieve Flavor and return a 404 response code", func() {
				router.Handle("/flavors/{id}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavors/cf197a51-8362-465f-9ec1-d88ad0023a27", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))

				var sfs []*wls.SignedImageFlavor
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).To(HaveOccurred())
				Expect(sfs).To(BeNil())

			})
		})
	})
})
