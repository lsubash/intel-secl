/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/domain/mocks"
	wlsRoutes "github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var SampleSamlReportPath = "../../ihub/test/resources/saml_report.xml"

var _ = Describe("KeyController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var keyController *controllers.KeyController

	BeforeEach(func() {
		router = mux.NewRouter()
		var conf config.Configuration
		conf.HVSApiUrl = "http://localhost:1338/mtwilson/v2/"
		conf.AASApiUrl = "http://localhost:1336/aas/v1/"
		conf.WLS.Username = "wls"
		conf.WLS.Password = "password"
		certStore := mocks.NewFakeCertificatesStore()
		keyController = controllers.NewKeyController(&conf, certStore)
	})

	Describe("Retrieve key", func() {
		Context("A valid retrieve key request", func() {
			It("A HTTP Status: 400 response is received", func() {
				k := mockKBS(":1337")
				defer k.Close()
				h := mockHVS(":1338")
				defer h.Close()
				a := mockAAS(":1336")
				defer a.Close()
				time.Sleep(1 * time.Second)

				router.Handle("/keys", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(keyController.RetrieveKey))).Methods(http.MethodPost)
				createfReq := `{
					"hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
					"key_url": "http://localhost:1337/v1/keys/98cb8e99-389a-4fdc-a430-e5c0ab7d7a40/transfer"
				}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
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

		Context("When invalid hardware uuid format is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle("/keys", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(keyController.RetrieveKey))).Methods(http.MethodPost)
				createfReq := `{
					"hardware_uuid": "964vv-89C1-E711-906E-00163566263E",
					"key_url": "http://localhost:1337/v1/keys/eb61b2e9-c7cd-4476-ac5f-71582c892112/transfer"
				}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
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

		Context("Invalid retrieve key request", func() {
			It("A HTTP Status: 400 response is received", func() {
				k := mockKBS(":1337")
				defer k.Close()
				h := mockHVS(":1338")
				defer h.Close()
				a := mockAAS(":1336")
				defer a.Close()
				time.Sleep(1 * time.Second)

				router.Handle("/keys", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(keyController.RetrieveKey))).Methods(http.MethodPost)

				var invalidCreateReq bytes.Buffer
				err := json.NewEncoder(&invalidCreateReq).Encode("#@!$")

				if err != nil {
					log.Fatal(err)
				}

				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
					&invalidCreateReq,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Invalid retrieve key request with Invalid key url", func() {
			It("A HTTP Status: 400 response is received", func() {
				k := mockKBS(":1337")
				defer k.Close()
				h := mockHVS(":1338")
				defer h.Close()
				a := mockAAS(":1336")
				defer a.Close()
				time.Sleep(1 * time.Second)

				router.Handle("/keys", wlsRoutes.ErrorHandler(wlsRoutes.JsonResponseHandler(keyController.RetrieveKey))).Methods(http.MethodPost)
				createfReq := `{
					"hardware_uuid": "00ecd3ab-9af4-e711-906e-001560a04062",
					"key_url": ""
				}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/keys",
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
})

func mockHVS(addr string) *http.Server {
	log.Trace("resource/common_test:mockHVS() Entering")
	defer log.Trace("resource/common_test:mockHVS() Leaving")
	r := mux.NewRouter()
	r.HandleFunc("/mtwilson/v2/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlassertion+xml")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		samlReport, err := ioutil.ReadFile(SampleSamlReportPath)
		log.Error(err)
		pattern := regexp.MustCompile(`( *)<`)
		samlReport = []byte(pattern.ReplaceAllString(string(samlReport), "<"))
		_, err = w.Write(samlReport)
		log.Error(err)
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

func Test_TransferKey(t *testing.T) {

	var conf config.Configuration
	conf.HVSApiUrl = "http://localhost:1338/mtwilson/v2/"
	conf.AASApiUrl = "http://localhost:1336/aas/v1/"
	conf.WLS.Username = "wls"
	conf.WLS.Password = "password"
	certStore := mocks.NewFakeCertificatesStore()

	k := mockKBS(":1337")
	defer k.Close()
	h := mockHVS(":1338")
	defer h.Close()
	a := mockAAS(":1336")
	defer a.Close()
	time.Sleep(1 * time.Second)

	type args struct {
		getFlavor bool
		hwid      string
		kUrl      string
		id        string
		cfg       *config.Configuration
		certStore *crypt.CertificatesStore
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Having getFlavor true for images API and key retrival should pass",
			args: args{
				getFlavor: true,
				hwid:      "00ecd3ab-9af4-e711-906e-001560a04062",
				kUrl:      "http://localhost:1337/v1/keys/98cb8e99-389a-4fdc-a430-e5c0ab7d7a40/transfer",
				id:        "98cb8e99-389a-4fdc-a430-e5c0ab7d7a40",
				cfg:       &conf,
				certStore: certStore,
			},
			want:    []byte(""),
			wantErr: false,
		},
		{
			name: "Should fail for parsing invalid url",
			args: args{
				getFlavor: true,
				hwid:      "00ecd3ab-9af4-e711-906e-001560a04062",
				kUrl:      "_20_+off_60000_%",
				id:        "98cb8e99-389a-4fdc-a430-e5c0ab7d7a40",
				cfg:       &conf,
				certStore: certStore,
			},
			want:    []byte(""),
			wantErr: true,
		},
		{
			name: "Should fail for Hvs client initialization",
			args: args{
				getFlavor: true,
				hwid:      "00ecd3ab-9af4-e711-906e-001560a04062",
				kUrl:      "http://localhost:1337/v1/keys/98cb8e99-389a-4fdc-a430-e5c0ab7d7a40/transfer",
				id:        "98cb8e99-389a-4fdc-a430-e5c0ab7d7a40",
				cfg:       &conf,
				certStore: certStore,
			},
			want:    []byte(""),
			wantErr: true,
		},
		{
			name: "Should fail for reports clients",
			args: args{
				getFlavor: true,
				hwid:      "00ecd3ab-9af4-e711-906e-001560a04062",
				kUrl:      "http://localhost:1337/v1/keys/98cb8e99-389a-4fdc-a430-e5c0ab7d7a40/transfer",
				id:        "98cb8e99-389a-4fdc-a430-e5c0ab7d7a40",
				cfg:       &conf,
				certStore: certStore,
			},
			want:    []byte(""),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.name == "Should fail for Hvs client initialization" {
				tt.args.cfg.HVSApiUrl = ""
			} else if tt.name == "Should fail for reports clients" {
				tt.args.cfg.HVSApiUrl = "_20_+off_60000_%"
			} else {
				tt.args.cfg.HVSApiUrl = "http://localhost:1338/mtwilson/v2/"
			}

			_, err := controllers.TransferKey(tt.args.getFlavor, tt.args.hwid, tt.args.kUrl, tt.args.id, tt.args.cfg, tt.args.certStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransferKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
