/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v5/pkg/wls/domain/mocks"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	wlsModel "github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	wlsRoutes "github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

var _ = Describe("ImageController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var imageStore *mocks2.MockImageStore
	var flavorStore *mocks2.MockFlavorStore
	var imageController *controllers.ImageController
	var certStore *crypt.CertificatesStore
	certStore = crypt.LoadCertificates(mocks2.NewFakeCertificatesPathStore(), wlsModel.GetUniqueCertTypes())

	BeforeEach(func() {
		router = mux.NewRouter()
		imageStore = mocks2.NewMockImageStore()
		flavorStore = mocks2.NewMockFlavorStore()
		var conf config.Configuration
		conf.HVSApiUrl = "http://localhost:1338/mtwilson/v2/"
		conf.AASApiUrl = "http://localhost:1336/aas/v1/"
		conf.WLS.Username = "wls"
		conf.WLS.Password = "password"

		imageController = controllers.NewImageController(imageStore, flavorStore, &conf, certStore)
	})

	Describe("RetrieveFlavorAndKey", func() {

		Context("When a valid image id is passed", func() {
			It("A HTTP Status: 200 response is received", func() {
				k := mockKBS(":1337")
				defer k.Close()
				h := mockHVS(":1338")
				defer h.Close()
				a := mockAAS(":1336")
				defer a.Close()
				time.Sleep(1 * time.Second)

				router.Handle("/images/{id}/flavor-key", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorAndKey))).Methods(http.MethodGet).Queries("hardware_uuid", "{hardware_uuid}")
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavor-key?hardware_uuid=00964993-89C1-E711-906E-00163566263E", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("When an invalid image id is passed", func() {
			It("A HTTP Status: 404 response is received", func() {
				router.Handle("/images/{id}/flavor-key", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorAndKey))).Methods(http.MethodGet).Queries("hardware_uuid", "{hardware_uuid}")
				req, err := http.NewRequest(http.MethodGet, "/images/1d61f86c-c522-4506-a3a0-a97e85c8d33e/flavor-key?hardware_uuid=00964993-89C1-E711-906E-00163566263E", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("When an invalid hardware uuid is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/images/{id}/flavor-key", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorAndKey))).Methods(http.MethodGet).Queries("hardware_uuid", "{hardware_uuid}")
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavor-key?hardware_uuid=1d61f86c-c522-4506-a3a0-a97e85c8d33", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("When wrong format image id is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/images/{id}/flavor-key", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorAndKey))).Methods(http.MethodGet).Queries("hardware_uuid", "{hardware_uuid}")
				req, err := http.NewRequest(http.MethodGet, "/images/kfff021e-9669-4e53-9224-8880fb4e408/flavor-key?hardware_uuid=1d61f86c-c522-4506-a3a0-a97e85c8d33", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
	//UpdateAssociatedFlavor
	Describe("Update Associated Flavor", func() {
		Context("when a valid image id and flavor ID is provided", func() {
			It("Should return 200", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.UpdateAssociatedFlavor))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/3d41c64f-ee70-4cbf-bdde-a03835a21625", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("When invalid flavor uuid format is provided", func() {
			It("Should return 400", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.UpdateAssociatedFlavor))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/xd41c64f-ee70-4cbf-bdde-a03835a2162", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("When invalid image uuid format is provided", func() {
			It("Should return 400", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.UpdateAssociatedFlavor))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/xfff021e-9669-4e53-9224-8880fb4e4081/flavors/3d41c64f-ee70-4cbf-bdde-a03835a21625", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})
	Describe("Create Image", func() {
		Context("When a empty Image Create Request is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Create))).Methods(http.MethodPost)
				// Create Request body
				createfReq := ``
				req, err := http.NewRequest(
					http.MethodPost,
					"/images",
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
		Context("When invalid content-type is passed", func() {
			It("A HTTP Status: 415 response is received", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Create))).Methods(http.MethodPost)
				// Create Request body
				createfReq := ``
				req, err := http.NewRequest(
					http.MethodPost,
					"/images",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypePemFile)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("When a VALID Image Create Request is passed", func() {
			It("A new Image record is created and HTTP Status: 201 response is received", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Create))).Methods(http.MethodPost)

				createfReq := `{
		   				 "id": "ffff021e-9669-4e53-9224-8880fb4e4081",
				"flavor_ids": [
		        "9541a9f0-b427-4a0a-8e25-12f50edd3e66"
		    ]
		}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/images",
					strings.NewReader(createfReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("When invalid JSON body is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Create))).Methods(http.MethodPost)

				createfReq := `{
		   				 "id": "ffff021e-9669-4e53-9224-8880fb4e4081",
		    ]
		}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/images",
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
	// Specs for HTTP Get to "/images"
	Describe("Search images", func() {

		Context("When filtered by image id and flavor id", func() {
			It("Should get a single Flavor entry and a 200 response code", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images?image_id=ffff021e-9669-4e53-9224-8880fb4e4081&flavor_id=9541a9f0-b427-4a0a-8e25-12f50edd3e66", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var imgResultSet []model.Image
				err = json.Unmarshal(w.Body.Bytes(), &imgResultSet)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(imgResultSet)).To(Equal(1))
			})
		})

		Context("When filtered by Image id", func() {
			It("Should get a single Flavor entry and a 200 response code", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images?image_id=ffff021e-9669-4e53-9224-8880fb4e4081", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var imgResultSet []model.Image
				err = json.Unmarshal(w.Body.Bytes(), &imgResultSet)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(imgResultSet)).To(Equal(1))

			})
		})

		Context("When invalid image uuid format is passed", func() {
			It("Should return 400", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images?image_id=xd61f86c-c522-4506-a3a0-a97e85c8d33", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When invalid flavor uuid format is passed", func() {
			It("Should return 400", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images?flavor_id=xyz1f86c-c522-4506-a3a0-a97e85c8d33", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When a valid flavor id is passed", func() {
			It("Should return 200", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images?flavor_id=9541a9f0-b427-4a0a-8e25-12f50edd3e66", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var imgResultSet []model.Image
				err = json.Unmarshal(w.Body.Bytes(), &imgResultSet)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(imgResultSet)).To(Equal(1))
			})
		})

		Context("When filtered by Image id which doesn't exists", func() {
			It("Should get a empty list and a 200 response code", func() {
				router.Handle("/images", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images?image_id=1d61f86c-c522-4506-a3a0-a97e85c8d33e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})

	// Specs for HTTP DELETE to "/images/{image_id}"
	Describe("Delete Image by ID", func() {
		Context("Delete Image by ID from data store", func() {
			It("Should delete Image and return a 204 response code", func() {
				router.Handle("/images/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(imageController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/images/ffff021e-9669-4e53-9224-8880fb4e4081", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("When invalid image uuid format is passed", func() {
			It("Should not delete Image and return a 400 response code", func() {
				router.Handle("/images/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(imageController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/images/zfff021e-9669-4e53-9224-8880fb4e408", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Non-existing image id is passed", func() {
			It("Should fail to delete Flavor and return a 404 response code", func() {
				router.Handle("/images/{id}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(imageController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/images/cf197a51-8362-465f-9ec1-d88ad0023a27", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
	//DeleteImageFlavorAssociation
	Describe("Delete Image flavor association", func() {
		Context("A valid image id and flavor id is provided", func() {
			It("Should delete Image Flavor Association and return a 204 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(imageController.DeleteImageFlavorAssociation))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/58967607-6292-4d53-815c-5efbd1fc8818", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("When invalid image uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(imageController.DeleteImageFlavorAssociation))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/images/xfff021e-9669-4e53-9224-8880fb4e408/flavors/58967607-6292-4d53-815c-5efbd1fc8818", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When invalid flavor uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(imageController.DeleteImageFlavorAssociation))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/y8967607-6292-4d53-815c-5efbd1fc881", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Non existing image id and flavor id is provided", func() {
			It("Should fail to delete association and return a 404 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.ResponseHandler(imageController.DeleteImageFlavorAssociation))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/dfa22f83-b6dd-4bf3-9b07-ff1fa01eb69f", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
	//RetrieveImageByID
	// Specs for HTTP Retrieve to "/image/{image_id}"
	Describe("Retrieve Image by ID", func() {
		Context("A valid image ID is provided", func() {
			It("Should Retrieve image and return a 200 response code", func() {
				router.Handle("/images/{id}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("When invalid image uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/zfff021e-9669-4e53-9224-8880fb4e408", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Retrieve Image by incorrect ID from data store", func() {
			It("Should fail to Retrieve Image and return a 404 response code", func() {
				router.Handle("/images/{id}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/b3096138-692d-48fe-b386-81a9d67c085d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
	//RetrieveAssociatedFlavorByFlavorPart
	Describe("Retrieve complete Flavor by image ID and flavor_part", func() {
		Context("A valid image ID and flavor_part is provided", func() {
			It("Should Retrieve Flavor and return a 200 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorForFlavorPart))).Methods(http.MethodGet).Queries("flavor_part", "{flavor_part}")
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors?flavor_part=IMAGE", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

			})
		})

		Context("Non existing image is provided", func() {
			It("Should not Retrieve flavor and return a 404 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorForFlavorPart))).Methods(http.MethodGet).Queries("flavor_part", "{flavor_part}")
				req, err := http.NewRequest(http.MethodGet, "/images/b3096138-692d-48fe-b386-81a9d67c085d/flavors?flavor_part=IMAGE", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("When Flavor part is null", func() {
			It("Should not Retrieve flavor and return a 400 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorForFlavorPart))).Methods(http.MethodGet).Queries("flavor_part", "{flavor_part}")
				req, err := http.NewRequest(http.MethodGet, "/images/b3096138-692d-48fe-b386-81a9d67c085d/flavors?flavor_part=", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When Invalid string name is provided in flavor part", func() {
			It("Should not Retrieve flavor and return a 400 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorForFlavorPart))).Methods(http.MethodGet).Queries("flavor_part", "{flavor_part}")
				req, err := http.NewRequest(http.MethodGet, "/images/b3096138-692d-48fe-b386-81a9d67c085d/flavors?flavor_part=????", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When invalid flavor uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorForFlavorPart))).Methods(http.MethodGet).Queries("flavor_part", "{flavor_part}")
				req, err := http.NewRequest(http.MethodGet, "/images/z3096138-692d-48fe-b386-81a9d67c0/flavors?flavor_part=IMAGE", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Image ID and invalid flavor part is provided", func() {
			It("Should fail to Retrieve flavor and return a 400 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.RetrieveFlavorForFlavorPart))).Methods(http.MethodGet).Queries("flavor_part", "{flavor_part}")
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors?flavor_part=xjyzg", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	//GetAllAssociatedFlavors--RetrieveFlavors
	Describe("Retrieve all the flavor ids Associated with Image ID", func() {
		Context("A valid image ID is provided", func() {
			It("Should Retrieve all the associated Flavor and return a 200 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAllAssociatedFlavors))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("When invalid image uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAllAssociatedFlavors))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/zz61f86c-c522-4506-a3a0-a97e85c8d3/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Non-existing image ID is provided", func() {
			It("Should not Retrieve Flavor and return 404 response code", func() {
				router.Handle("/images/{id}/flavors", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAllAssociatedFlavors))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/1d61f86c-c522-4506-a3a0-a97e85c8d33e/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
	//GetAllAssociatedFlavor
	Describe("Retrieve the flavor Associated with Image ID", func() {

		Context("A valid image ID and flavor id is provided", func() {
			It("Should Retrieve associated Flavor and return a 200 response code", func() {
				router.Handle("/v2/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavor))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/v2/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/9541a9f0-b427-4a0a-8e25-12f50edd3e66", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Non existing image id and flavor id is provided", func() {
			It("Should not Retrieve Flavor and return a 404 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavor))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/1d61f86c-c522-4506-a3a0-a97e85c8d33e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("When invalid image uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavor))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/z021e-9669-4e53-9224-8880fb4e4081/flavors/1d61f86c-c522-4506-a3a0-a97e85c8d33e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("When invalid flavor uuid format is passed", func() {
			It("Should return a 400 response code", func() {
				router.Handle("/images/{id}/flavors/{flavorID}", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(imageController.GetAssociatedFlavor))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/z1f86c-c522-4506-a3a0-a97e85c8d33e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})
})

func mockHVS(addr string) *http.Server {
	log.Trace("resource/common_test:mockHVS() Entering")
	defer log.Trace("resource/common_test:mockHVS() Leaving")
	r := mux.NewRouter()
	r.HandleFunc("/mtwilson/v2/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlassertion+xml")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(saml))
	}).Methods(http.MethodPost)
	h := &http.Server{
		Addr:    addr,
		Handler: r,
	}
	go h.ListenAndServe()
	return h
}

const BearerToken = "eyJhbGciOiJSUzM4NCIsImtpZCI6IjRiNDA3MmYyNWQ1ZDk1ZWE2NjlmZWRhOWU4NGUzZjJiNWY5ZmM3YzQiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkFBUyIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn0seyJzZXJ2aWNlIjoiVEEiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IkFIIiwibmFtZSI6IkFkbWluaXN0cmF0b3IifSx7InNlcnZpY2UiOiJIVlMiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IktNUyIsIm5hbWUiOiJLZXlDUlVEIn0seyJzZXJ2aWNlIjoiV0xTIiwibmFtZSI6IkFkbWluaXN0cmF0b3IifV0sInBlcm1pc3Npb25zIjpbeyJzZXJ2aWNlIjoiQUFTIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiQUgiLCJydWxlcyI6WyIqOio6KiJdfSx7InNlcnZpY2UiOiJIVlMiLCJydWxlcyI6WyIqOio6KiJdfSx7InNlcnZpY2UiOiJLTVMiLCJydWxlcyI6WyIqOio6KiJdfSx7InNlcnZpY2UiOiJUQSIsInJ1bGVzIjpbIio6KjoqIl19LHsic2VydmljZSI6IldMUyIsInJ1bGVzIjpbIio6KjoqIl19XSwiZXhwIjoyMjI3MjUwNDAzLCJpYXQiOjE1OTY1MzAzNzMsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiZ2xvYmFsX2FkbWluX3VzZXIifQ.mT0IlmD6ZzBKv98maup6EkKQ5qAgFuz0wZ7AjB_O5TukEpcznGZfuXelR8awyDZcuC8wdjvUEubive6ip1QB-_6KV2TFdc85Am8eWRk8eRei0Na3JIh7yEh9rk-Xjv9lcj4uwm-fdNe2vJ7mSxs07gsRB-ufw0YA5fX5Xs_VxCCp3sPgBvSJS5DarRJDLAnbWEPRbnyP0HXnfkwGlQAvHcyi8kYEflOlsLDsUwZC9fxQEJRz2qteSU-BVUYzzlt8nMjSu8X5EDGAI4DVYk1WecO9DxbVWYa2Zu2yUnIbFake6bulTGvD4ahhkHA4anLtC9tgf3hOoHGabl7lplja2XCtGBHU_h4mJcGg-aH4EfM3jXjfwJdhnN_lihbcI7LSQ9yQFDAigALW6xPKLSbpH__cbvFooKw7eRcX6AY1x_8hLhBpnvsivzE51rxchsMJ1QC07HdZQQ_RU5Dcg5Kc2rtRnanlY8G7nZ_XXVmU_EG-rW8dintqZztvSHmStnz9"

func mockAAS(addr string) *http.Server {
	log.Trace("resource/common_test:mockAAS() Entering")
	defer log.Trace("resource/common_test:mockAAS() Leaving")
	r := mux.NewRouter()
	r.HandleFunc("/aas/v1/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(BearerToken))
	}).Methods(http.MethodPost)
	h := &http.Server{
		Addr:    addr,
		Handler: r,
	}
	go h.ListenAndServe()
	return h
}

func mockKBS(addr string) *http.Server {
	log.Trace("resource/common_test:mockKMS() Entering")
	defer log.Trace("resource/common_test:mockKMS() Leaving")
	r := mux.NewRouter()
	r.HandleFunc("/v1/keys/{keyId}/transfer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		enc, _ := base64.StdEncoding.DecodeString(`ibjvgE7lIdDqGrgf3CLY4xeOMdzU6K6c1dZO04U51Z7JomuaQCTgdtUbQUU5eJxnapV3lTO2ev3q
		pmnyCvR1fpwF7n/dQKRDVraLvuElABcJ33uQiVTxjBcCRIDmNRpBNjS0q6f7EuynUrbeqmEVFJWn
		v0U4smZd6s3x6krTP4BiOGttpDiR0TD5N9kbMJMBZvWvERkBMwRED/Nmt9JEdD0s3mHe5zV3G9WX
		ln40773Cczo9awtNfUVdVyDx6LejJcCgkt4XNdRZbK9cVdGK+w6Q1tASiVxRZmvJDVFA0Pa8F1I0
		I9Iri2+YRM6sGVg8ZkzcCmFd+CoTNy+cw/Y9AQ==`)
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write(enc)
	}).Methods(http.MethodPost)
	h := &http.Server{
		Addr:    addr,
		Handler: r,
	}
	go h.ListenAndServe()
	return h
}

var saml = `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="MapAssertion" IssueInstant="2021-12-07T12:31:06.711Z" Version="2.0"><saml2:Issuer>AttestationService</saml2:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#MapAssertion"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>f9ZaOikppN/C3ZW3ILPs7iB46yzEFfS/Px8oC7Fl2K0=</DigestValue></Reference></SignedInfo><SignatureValue>mNO3PVOd/wpkeu7vz2xpzd8BTacs321KXcHuc2iShfl3SQia+XO7TI2yuzj3B5oHR5Fov9tnqJxypzAkan/kkRB5DlvzonGICJv9qfQUgpe6RWeGUpy5JhaTtvHn8YuPpW0GqvzBbUEUJAMHzrScTRUE99z+PNdFzWhOQvmfTwPiZIPHxNez47kw94r+oJYhqpi6pKrAVX3oxdE9QW9qxcNjysohkKUrem+NcZcld2Ksx10C9apZ5EL4jwJIPL/661990av+Fty4pH1LmdSG1CNr9i8p49DwUifNrJXyCv/fsKaxQW7S9XSL6ZW/QT8O+6UXax/IrCN06jSXQINQ7P07F1j4It9i69RyZB+DQggLtSZ54na8Mi7V3VbkkyLc1/Y0oc9tybvrgb2TwSKq4OiONGKFvUQYeH+S0IvU4Np2rjyAPO5phLwD3hrrBPtytJylAuP4ICtoqy184koYrIJyRBy6XubqJVOeTlnxIoTLD0N3pr3zGbXMGtVUnWpT</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEHTCCAoWgAwIBAgIBCDANBgkqhkiG9w0BAQwFADBQMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwHhcNMjExMjA3MDYzMDM0WhcNMjIxMjA3MDYzMDM0WjAfMR0wGwYDVQQDExRIVlMgU0FNTCBDZXJ0aWZpY2F0ZTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAMS2lTL1bN6bGzyUQsys5RXbA1qV0nAd1jMDrC8FWW20mhproVZImXxV8Mhc691KBWS1yeywao7toC077tVqCF+kpjjniJJXOl5Z8ofzTZx5wk+u0a/mwcefTlWV4OOe2nO39w+noEda9oK87tC3B34yflyMh6rMgXC09cP+MJrZ5/HZKlueX8vaBg1tP8lE4hKCAXg5o9+OJpt4JL2yxkaov23YFwBMU83aWuzUTCFTqzXbZ84tJb42waASshoDzS4PJeSinwOocRJKhYErP4P8U0MFIeEBavfOI/L2g08b1ml1gTCci1lhaixzbcCeGgQRXYaAlNXrMWFm7obFEmjyOQ6ZwagzaHNoiYIzeJuj73uPwcUmmC+f3iYX0sM0URtxOyg75N1qydSysiAQGJTAtGUGNwuTJ3sMQjgoGvmrOtJKoOPB2PpxoY5ucVV/SL9mrMJ/i7Ij17X9roVXrw4sRj/itwa87nxBl1NDkNcL3wjkGbEnE7TprwSOqEV+LQIDAQABozMwMTAOBgNVHQ8BAf8EBAMCBsAwHwYDVR0jBBgwFoAUetYpCCf0PGBnTEdAPS6mvbF/EicwDQYJKoZIhvcNAQEMBQADggGBAKkQ6ZMelYFrQQkQnH3ix8/F9YVDQV3aCHiXfaW6CahEw+HgnoJAdhwh9/Gj/GoIs8tPe7BcJXPpC2FVMwcAPh5D8qjHd7ZhY2lVZoSurL4qlnjtK867nCmrGjPYXpgbBMSM/6L36D4yp7PVHYxuog6D6exaKP6DxqHtCFv3zhCSxL7RtTqwrghGhurNol7Yv6H01zS0ZAin62Q4gxNUzfW4QyIejLWA9y/Fk9eMzfcNwq2efSZGp3nYiZmtAWhmt0V7k/vewzJr+CRy5A8H2Fkx3XdCCBUIyb+26LlMcTLQTEm8aNPbJpaGtK0cjl5hkVB0koXSKNyIUqkL1/tJSIBD3Neue2KCAMgfb9s+JeRvTaImu6+1wScq9Hubsuopg7LQsKBuwKNzFeEWPdTS61ST3hbFktLDEJLdQqU8WveR7hlsU2CdIhcKhYvvZgWrQ/yCo3sTIc/ZcvdoM+Fek6AiwD8wrGMnaiLL9zLk8z8MsiBC7zwkYjosiSC2+C9P+w==</X509Certificate></X509Data></KeyInfo></Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">HVS</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/><saml2:SubjectConfirmationData NotBefore="2021-12-07T12:31:06.711Z" NotOnOrAfter="2021-12-08T12:31:06.711Z"/></saml2:SubjectConfirmation></saml2:Subject><saml2:AttributeStatement><saml2:Attribute Name="ProcessorInfo"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">54 06 05 00 FF FB EB BF</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="OSType"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">linux</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TRUST_PLATFORM"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TRUST_OS"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="ProcessorFlags"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="VMMVersion"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">6.0.0</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="AIK_Certificate"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">MIIDUDCCAbigAwIBAgIQayy190y275IhkZMqxAUZHzANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDExdIVlMgUHJpdmFjeSBDZXJ0aWZpY2F0ZTAeFw0yMTEyMDcwNzQ0NTNaFw0yNjEyMDcwNzQ0NTNaMCIxIDAeBgNVBAMTF0hWUyBQcml2YWN5IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmYNwM13ky/6bKGr4L6B5GqkTEy0EnFFYnYCHv3FF7rQ4k5zrA0u+yYd99877bAsRASUjxVznr45PPeSWBXOyk0vcNQI90ZUl+qUO7lUQ7wjpCD/zVN6RhgsW0ma/0sS+C3n62tXyrFVb3Hlwt3mJ9PX9jOb74vTVMOaSW6qgkc4YiUEl3io4+IT9gQbVSUBEEZZfX0OhedALOqwFr2MqqdHiKmUfZwv6WyHxsShST55hYQqAAfny64TKBdhYXe5GknZu5VwqUtgDX161HFb4/F0b7/gJTrnfptUsfxUhd6lm+q8PiQa/NM50Jv179yOP44JhkvFUwdGY4pHpjk9+mwIDAQABowIwADANBgkqhkiG9w0BAQsFAAOCAYEAc+52doq8QDkQ8Z67rQ9u+T4iVRMTx53vZzbvxPB7/sRIjQv7hrSItwIm9BPTevRliOLEj5M7qTgeTKYdumRAtPv0Awc2CyLBAVtxmrJDtUKyPP/wWWD0uKH+LwUAzUv1hpwZRufVq/Ndd3R+wAwh7KAA8DmmhlKo/yjMhLh4lpeNkJWfz5F0UjpdK16HiWHdDaMNkx8aYsauzap8BV0OG/4xzpHPjjfaYXOhzhnBnWF7b2pIVr5rUL93T3YvV040jOMJ/jt+jDu/E7hDgnVUa5ds4r1qI0bmqaARk6D2HRRVXKgky90kO2S1RtkJpR4+m6MeH5jnTYzdIKu6opMtPNudpUo7z2Au+ySpBVXLm/r7M+EqdbiMk29lsWPnWpNgaGnnJeFPzVMq73HhQjpjoHrV1oq1Pl1WlBBOa0oESxyjDb/kvz/OP1LzF9IIQSyf+2h2Wps4zCtoKubJsUidmT/6upBpzOC31M7dD4kmz7RNd8jTqLlZTxZwddR076sz</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="FEATURE_UEFI"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TRUST_HOST_UNIQUE"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="FEATURE_SecureBootEnabled"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">false</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="FEATURE_TPM"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="FEATURE_TXT"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="BiosName"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">Intel Corporation</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="NumberOfSockets"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">72</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="InstalledComponents"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">[tagent wlagent]</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Binding_Key_Certificate"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">MIIFPjCCA6agAwIBAgIRANLH6nUhlx2s5L6P0/9X4EkwDQYJKoZIhvcNAQEMBQAwIjEgMB4GA1UEAxMXSFZTIFByaXZhY3kgQ2VydGlmaWNhdGUwHhcNMjExMjA3MDc0NjQ3WhcNMzExMjA3MDc0NjQ3WjAiMSAwHgYDVQQDDBdCaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJzv5SeSsqc+BR+dl/5/cvGCgtyOqXKOPW9seBnD8QZs/NmNWg1cKylUVXuwehrvze0G+Hb6ZNB/7ymd+rP7Qq6N951i1EQRVVmuY+ilajS+Au7nId2NFQ7ySgoePP5jRSDVD/h13lBa1pB/N+onUkJdAgCEEgp8jWMUFISLKpomEqxnNjWZUxKWfWcP0jspSB4by6ONRbumXqDqRgdIIvujZPC0/ae8j6MLd9iNJuuA32KviKWy294mdkGLWgj3Wf6yK1vz8F7vYMKwgcrxcFYQqGZfler6ijfkr04r+q+9oy1O6kQbmFLOuSodLM8aiImATitvkwuVbLyESVBp/hcCAwEAAaOCAe0wggHpMA4GA1UdDwEB/wQEAwIFoDAfBgNVHSMEGDAWgBRy9/ncX/pZ5leSXT8UxjRk4mbxfjCBnQYHVQSBBQMCKQSBkf9UQ0eAFwAiAAurblhbVUgP11fKNyruKRjauGIuj1wRXssXzSpNl6iFywAEAP9VqgAAAAAADC/BAAAABAAAAAEBAAcAKAAIMgAAIgALKSRrimAPeF7Tfer+r9NVVEr9CVBSgRs7Nt+pB5OsFPMAIgAL/s9OsAph+SnpFEUIXOSCBaL5ip4nsvvRQAFtn08g7jQwggEUBghVBIEFAwIpAQSCAQYAFAALAQB1mYsVBth1G0Q+S6aX8h/zf1qwoPG8xdQGCfaOm60slyo5ynm2DXLzpw8NiBvYmFOYtrlDKyo7i7fnynMtOsCV+Rs4zmrsn9U5g6i7HhHJPcon6rMe4gSdaUOwopg5Rkk/q/uiqPvQLBr3/OlgI7shB75VzBtaiVwEvjSUrDxguGbEs5t/QudK/poGPrZCng/4gftWzBRGMR6sAQltRa/REIiI5gkh930b12BG4V2JjMTkO5qTqPiAM00Jg4WSuyaIEhoIMEiuOxTtHRWUhxFhFk6cNjl5Iizbc/qejH2T3RnttVBlW9JLbIjy9iyp2xsOMwxpgIeDjlEdCixv6TceMA0GCSqGSIb3DQEBDAUAA4IBgQAleLTePGWrZzaPEUCasH9PsDNAPOytfKdvSQhtjGjQ5Ztj1MRNNgCeBXGNwdoVnAyE++qlpH53i2RJS5KCWNaeDy6UMjr7zJ9CTllURQ4rVbkg/dZGZ9t7N4BKtTAGB4GO0vQNT4tYJhZQSgfvLe21K7Z0NSF2LOwMJJV8P8kREbz+aRni4S0bpCrZDWWV6MOyEQM2ESPfBiFiQGM5yS0QE+bQydTtnQN0GTXEndQzULo7Vg7pocpkOfCQQ+3o5XBU+2AgpHhM/OKHWSQOvUIL9rSlyqlY0pPI9HA5FoKICC++rYmC7uD2xIcIpGEoX3dJTGmJ5TlnJeUACAr6gkRWR7VLfkZiLXTynkMDpcF6J0DUX0rXzkjHif5zxQftZDpA9e8GfnPxOu2b0vQQe6pJ0m+pNLys61eBK6YNJiSsq9EY4LB14VjzMnCQmh3drP4gpllQmtOP7KYFQ8gn/0jf/Kk60mDeupPEH6tmkC3+kPSjBRzPtDfi4/9eBMsSUrc=</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="OSName"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">RedHatEnterprise</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TRUST_ASSET_TAG"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">NA</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TRUST_OVERALL"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TbootInstalled"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="BiosVersion"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">SE5C620.86B.00.01.0015.110720180833</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="VMMName"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">Virsh</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="HostName"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">10.105.167.120</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="OSVersion"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">8.4</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="HardwareUUID"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">00ecd3ab-9af4-e711-906e-001560a04062</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TPMVersion"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">2.0</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="IsDockerEnvironment"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">false</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="TRUST_SOFTWARE"><saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>`
