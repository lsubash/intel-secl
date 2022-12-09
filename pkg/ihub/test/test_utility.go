/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package testutility

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
)

// AASToken token for AAS
var AASToken = "eyJhbGciOiJSUzM4NCIsImtpZCI6ImU5NjI1NzI0NTUwNzMwZGI3N2I2YmEyMjU1OGNjZTEyOTBkNjRkNTciLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyUm9sZU1hbmFnZXIifSx7InNlcnZpY2UiOiJUQSIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn0seyJzZXJ2aWNlIjoiVlMiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IktNUyIsIm5hbWUiOiJLZXlDUlVEIn0seyJzZXJ2aWNlIjoiQUgiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IldMUyIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn1dLCJwZXJtaXNzaW9ucyI6W3sic2VydmljZSI6IkFIIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiS01TIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiVEEiLCJydWxlcyI6WyIqOio6KiJdfSx7InNlcnZpY2UiOiJWUyIsInJ1bGVzIjpbIio6KjoqIl19LHsic2VydmljZSI6IldMUyIsInJ1bGVzIjpbIio6KjoqIl19XSwiZXhwIjoxNTk0NDgxMjAxLCJpYXQiOjE1OTQ0NzQwMDEsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiZ2xvYmFsX2FkbWluX3VzZXIifQ.euPkZEv0P9UC8ni05hb5wczFa9_C2G4mNAl4nVtBQ0oS-00qK4wC52Eg1UZqAjkVWXafHRcEjjsdQHs1LtjECFmU6zUNOMEtLLIOZwhnD7xlHkC-flpzLMT0W5162nsW4xSp-cF-r_05C7PgFcK9zIfMtn6_MUMcxlSXkX21AJWwfhVfz4ogEY2mqt73Ramd1tvhGbsz7i3XaljnopSTV7djNMeMZ33MPzJYGl5ph_AKBZwhBTA0DV3JAPTE9jXqrhtOG1iR1yM9kHChskzxAaRDm0v3V07ySgkxyv7dAzMW5Ek_NGCulyjP5N_WgSeuTkw26A8kZpSrNRWdbnyOr_EZ4y6wDX9GMARrR4PyTb6hU9x3ejahxs3L_Z7BzbYpO4WF1CvlYl5BoH71PnFPNKMkvbIFv1XcLPwKeLQpohEOr7zEN4EeltjpqBGCgiCFz4vHu5rk2iFCu1JJPDTVR3jJplJRZgCFiwsh42R3oomP-q43k8_PPLIMjaxAADgd"

// K8sToken token for k8s
var K8sToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"

// SampleSamlCertPath sample Certificate Path
var SampleSamlCertPath = "../test/resources/saml_certificate.pem"

// SampleSamlReportPath  sample Report Path
var SampleSamlReportPath = "../test/resources/saml_report.xml"

// SampleListOfNodesFilePath sample json for K8s Nodes
var SampleListOfNodesFilePath = "../test/resources/list_of_nodes.json"

// CustomCRDFilePath sample json for custom CRD
var CustomCRDFilePath = "../test/resources/custom_crd.json"

// K8scertFilePath sample for k8sCertFilePath
var K8scertFilePath = "../test/resources/k8scert.pem"

// SGXPlatformDataFilePath sample json
var SGXPlatformDataFilePath = "../../ihub/test/resources/sgx_platform_data.json"

// MockServer for IHUB unit testing
func MockServer(t *testing.T) *httptest.Server {
	r := mux.NewRouter()

	r.HandleFunc("/aas/v1/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(AASToken))
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodPost)

	r.HandleFunc("/hvs/v2/invalid/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write(nil)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/hvs/v2/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		samlReport, err := ioutil.ReadFile(SampleSamlReportPath)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to read file", err)
		}
		pattern := regexp.MustCompile(`( *)<`)
		samlReport = []byte(pattern.ReplaceAllString(string(samlReport), "<"))
		_, err = w.Write(samlReport)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/hvs/v2/ca-certificates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		samlCertificate, err := ioutil.ReadFile(SampleSamlCertPath)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to read file", err)
		}
		_, err = w.Write(samlCertificate)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	//K8s URLs
	r.HandleFunc("/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/custom-isecl2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		customCRD, err := ioutil.ReadFile(CustomCRDFilePath)
		if err != nil {
			t.Log("mockServer() : Unable to read file", err)
		}
		_, err = w.Write(customCRD)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	//K8s URLs
	r.HandleFunc("/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/custom-isecl-not-found", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.WriteHeader(http.StatusNotFound)
		_, err := w.Write([]byte(""))
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/custom-isecl-not-found", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}).Methods(http.MethodPost)

	r.HandleFunc("/apis/crd.isecl.intel.com/v1beta1/namespaces/default/hostattributes/custom-isecl2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}).Methods(http.MethodPut)

	r.HandleFunc("/api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		listOfNodes, err := ioutil.ReadFile(SampleListOfNodesFilePath)
		if err != nil {
			t.Log("mockServer() : Unable to read file", err)
		}
		_, err = w.Write(listOfNodes)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/apis", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		customCRD, err := ioutil.ReadFile(CustomCRDFilePath)
		if err != nil {
			t.Log("mockServer() : Unable to read file", err)
		}
		_, err = w.Write(customCRD)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/sgx-hvs/v2/platform-data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		SGXPlatformData, err := ioutil.ReadFile(SGXPlatformDataFilePath)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to read file", err)
		}
		_, err = w.Write(SGXPlatformData)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/sgx-hvs/v2/platform-data?HostName=worker-node1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		SGXPlatformData, err := ioutil.ReadFile(SGXPlatformDataFilePath)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to read file", err)
		}
		_, err = w.Write(SGXPlatformData)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/sgx-hvs/v2/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}).Methods(http.MethodGet)

	return httptest.NewServer(r)
}

// SetupMockK8sConfiguration setting up mock k8s configurations
func SetupMockK8sConfiguration(t *testing.T, serverUrl string) *config.Configuration {

	temp, _ := ioutil.TempFile("", "config.yml")
	defer func() {
		derr := os.Remove(temp.Name())
		if derr != nil {
			log.WithError(derr).Errorf("Error removing file")
		}
	}()
	c, _ := config.LoadConfiguration()
	c.AASBaseUrl = serverUrl + "/aas/v1/"
	c.IHUB.Username = "admin@hub"
	c.IHUB.Password = "hubAdminPass"
	c.AttestationService.HVSBaseURL = serverUrl + "/hvs/v2/"
	c.AttestationService.SHVSBaseURL = serverUrl + "/sgx-hvs/v2/"
	c.Endpoint.Type = "KUBERNETES"
	c.Endpoint.URL = serverUrl + "/"
	c.Endpoint.CRDName = "custom-isecl"
	c.Endpoint.CertFile = K8scertFilePath
	c.Endpoint.Token = K8sToken

	return c
}
