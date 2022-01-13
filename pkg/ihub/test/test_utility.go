/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package testutility

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	openstackClient "github.com/intel-secl/intel-secl/v5/pkg/clients/openstack"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
)

//IhubServiceUserName sample user name
var IhubServiceUserName = "admin@hub"

//IhubServicePassword sample user password
var IhubServicePassword = "hubAdminPass"

//AASToken token for AAS
var AASToken = "eyJhbGciOiJSUzM4NCIsImtpZCI6ImU5NjI1NzI0NTUwNzMwZGI3N2I2YmEyMjU1OGNjZTEyOTBkNjRkNTciLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyUm9sZU1hbmFnZXIifSx7InNlcnZpY2UiOiJUQSIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn0seyJzZXJ2aWNlIjoiVlMiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IktNUyIsIm5hbWUiOiJLZXlDUlVEIn0seyJzZXJ2aWNlIjoiQUgiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IldMUyIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn1dLCJwZXJtaXNzaW9ucyI6W3sic2VydmljZSI6IkFIIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiS01TIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiVEEiLCJydWxlcyI6WyIqOio6KiJdfSx7InNlcnZpY2UiOiJWUyIsInJ1bGVzIjpbIio6KjoqIl19LHsic2VydmljZSI6IldMUyIsInJ1bGVzIjpbIio6KjoqIl19XSwiZXhwIjoxNTk0NDgxMjAxLCJpYXQiOjE1OTQ0NzQwMDEsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiZ2xvYmFsX2FkbWluX3VzZXIifQ.euPkZEv0P9UC8ni05hb5wczFa9_C2G4mNAl4nVtBQ0oS-00qK4wC52Eg1UZqAjkVWXafHRcEjjsdQHs1LtjECFmU6zUNOMEtLLIOZwhnD7xlHkC-flpzLMT0W5162nsW4xSp-cF-r_05C7PgFcK9zIfMtn6_MUMcxlSXkX21AJWwfhVfz4ogEY2mqt73Ramd1tvhGbsz7i3XaljnopSTV7djNMeMZ33MPzJYGl5ph_AKBZwhBTA0DV3JAPTE9jXqrhtOG1iR1yM9kHChskzxAaRDm0v3V07ySgkxyv7dAzMW5Ek_NGCulyjP5N_WgSeuTkw26A8kZpSrNRWdbnyOr_EZ4y6wDX9GMARrR4PyTb6hU9x3ejahxs3L_Z7BzbYpO4WF1CvlYl5BoH71PnFPNKMkvbIFv1XcLPwKeLQpohEOr7zEN4EeltjpqBGCgiCFz4vHu5rk2iFCu1JJPDTVR3jJplJRZgCFiwsh42R3oomP-q43k8_PPLIMjaxAADgd"

//K8sToken token for k8s
var K8sToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"

//OpenstackAuthToken token for openstack
var OpenstackAuthToken = "eyJhbGciOiJSUzM4NCIsImtpZCI6ImU5NjI1NzI0NTUwNzMwZGI3N2I2YmEyMjU1OGNjZTEyOTBkNjRkNTciLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyUm9sZU1hbmFnZXIifSx7InNlcnZpY2UiOiJUQSIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn0seyJzZXJ2aWNlIjoiVlMiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IktNUyIsIm5hbWUiOiJLZXlDUlVEIn0seyJzZXJ2aWNlIjoiQUgiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9LHsic2VydmljZSI6IldMUyIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIn1dLCJwZXJtaXNzaW9ucyI6W3sic2VydmljZSI6IkFIIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiS01TIiwicnVsZXMiOlsiKjoqOioiXX0seyJzZXJ2aWNlIjoiVEEiLCJydWxlcyI6WyIqOio6KiJdfSx7InNlcnZpY2UiOiJWUyIsInJ1bGVzIjpbIio6KjoqIl19LHsic2VydmljZSI6IldMUyIsInJ1bGVzIjpbIio6KjoqIl19XSwiZXhwIjoxNTkzNTMwNTA1LCJpYXQiOjE1OTM1MjMzMDUsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiZ2xvYmFsX2FkbWluX3VzZXIifQ.L511cVpP-UFYY4vNgqRXKFXt6aTf4W3EchC_Ob-O2A3NzOGbyuYqg_2KXsFQVSYirNdLhpp5AvjRdGM0MKOXhyzZ62yHK0NLRSCFNKiY2cjTqbA14rRlWaZhB23INo3TW8jmIf90FzBn59L9zlXFDl0Zl93yg4lVX47W7oztuaoTTTCxAbSMY0lm0UI1Krosq6ugqzDQK-_7XESppO48UC2FpXl-gm6FxlqVPWWNxgsrgfd7ag3BeuFhLyY8Vg_J-RqwdpZig-1VVCiIss4EizYrAbYNxOEDcxI7OUuUcRS3-B50mGt5TzZ6MTNNyb7H1D4_7AIklRJBaqSO0FBQQy0ff2mDxPTc1vKfjqlIJDbAgZTM0DvzsBw7hUk9EQAbutqLp2Rs8zWt-X0Ni2da8wGVEdLosuu6KfUOdj1kKNHqwtjI-iVtV63oIllocqfQXS9FORJH9d284o6yalUjoTZ2gRTm936FuGGtWesAFkDJFrIgoNUiZ7AIdo_IJEbR"

//SampleSamlCertPath sample Certificate Path
var SampleSamlCertPath = "../test/resources/saml_certificate.pem"

//SampleSamlReportPath  sample Report Path
var SampleSamlReportPath = "../test/resources/saml_report.xml"

//SampleListOfNodesFilePath sample json for K8s Nodes
var SampleListOfNodesFilePath = "../test/resources/list_of_nodes.json"

//CustomCRDFilePath sample json for custom CRD
var CustomCRDFilePath = "../test/resources/custom_crd.json"

//K8scertFilePath sample for k8sCertFilePath
var K8scertFilePath = "../test/resources/k8scert.pem"

//AuthenticationResponseFilePath sample Authentication Response json
var AuthenticationResponseFilePath = "../test/resources/auth_response.json"

//AllTraitsFilePath sample All traits json
var AllTraitsFilePath = "../test/resources/all_traits.json"

//ResourceTraitsFilePath sample Traits for resources json
var ResourceTraitsFilePath = "../test/resources/resource_traits.json"

//OpenstackResourcesFilePath sample Resources json
var OpenstackResourcesFilePath = "../test/resources/openstack_resources.json"

//SGXPlatformDataFilePath sample json
var SGXPlatformDataFilePath = "../../ihub/test/resources/sgx_platform_data.json"

//SGXPlatformDataFilePathBadEpcSize sample json with bad EPC size
var SGXPlatformDataFilePathBadEpcSize = "../../ihub/test/resources/sgx_platform_data_badepcsize.json"

//OpenstackUserName Sample Openstack UserName
var OpenstackUserName = "admin"

//OpenstackPassword sample Openstack Password
var OpenstackPassword = "password"

//OpenstackHostID sample Openstack HostID
var OpenstackHostID = "2f309eb2-71fa-4d67-83a4-de5ca3fc2e05"

//InvalidOpenstackHostID sample Openstack HostID
var InvalidOpenstackHostID = "2g309dc2-71gb-4d67-83a4-de5ca3fc2e05"

// MockServer for IHUB unit testing
func MockServer(t *testing.T) *httptest.Server {
	r := mux.NewRouter()

	r.HandleFunc("/aas/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(AASToken))
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodPost)

	r.HandleFunc("/mtwilson/v2/invalid/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write(nil)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/mtwilson/v2/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		samlReport, err := ioutil.ReadFile(SampleSamlReportPath)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to read file", err)
		}
		_, err = w.Write(samlReport)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/mtwilson/v2/ca-certificates", func(w http.ResponseWriter, r *http.Request) {
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

	//Openstack Listeners
	r.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		var auth openstackClient.Authorization
		err := json.NewDecoder(r.Body).Decode(&auth)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to decode auth")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if OpenstackUserName == auth.Auth.Identity.Password.User.Name && OpenstackPassword == auth.Auth.Identity.Password.User.Password {
			w.Header().Set("X-Subject-Token", OpenstackAuthToken)
			authenticationResponse, err := ioutil.ReadFile(AuthenticationResponseFilePath)
			if err != nil {
				t.Log("mockServer() : Unable to read file", err)
			}
			_, err = w.Write(authenticationResponse)
			if err != nil {
				t.Log("test/test_utility:mockServer(): Unable to write data")
			}
			w.WriteHeader(201)
		} else {
			w.Header().Set("X-Subject-Token", "")
			_, err := w.Write([]byte(""))
			if err != nil {
				t.Log("test/test_utility:mockServer(): Unable to write data")
			}
			w.WriteHeader(401)
		}
	}).Methods(http.MethodPost)

	r.HandleFunc("/openstack/api/resource_providers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if OpenstackAuthToken == r.Header.Get("x-auth-token") {
			openstackResources, err := ioutil.ReadFile(OpenstackResourcesFilePath)
			if err != nil {
				t.Log("mockServer() : Unable to read file", err)
			}
			_, err = w.Write(openstackResources)
			if err != nil {
				t.Log("test/test_utility:mockServer(): Unable to write data")
			}
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/openstack/api/resource_providers/2f309eb2-71fa-4d67-83a4-de5ca3fc2e05/traits", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if OpenstackAuthToken == r.Header.Get("x-auth-token") {
			resourceTraits, err := ioutil.ReadFile(ResourceTraitsFilePath)
			if err != nil {
				t.Log("mockServer() : Unable to read file", err)
			}
			_, err = w.Write(resourceTraits)
			if err != nil {
				t.Log("test/test_utility:mockServer(): Unable to write data")
			}
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}).Methods(http.MethodGet)

	r.HandleFunc("/openstack/api/resource_providers/2f309eb2-71fa-4d67-83a4-de5ca3fc2e05/traits", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if OpenstackAuthToken == r.Header.Get("x-auth-token") {
			resourceTraits, err := ioutil.ReadFile(ResourceTraitsFilePath)
			if err != nil {
				t.Log("mockServer() : Unable to read file", err)
			}
			_, err = w.Write(resourceTraits)
			if err != nil {
				t.Log("test/test_utility:mockServer(): Unable to write data")
			}
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}).Methods(http.MethodPut)

	r.HandleFunc("/openstack/api/traits", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if OpenstackAuthToken == r.Header.Get("x-auth-token") {
			allTraits, err := ioutil.ReadFile(AllTraitsFilePath)
			if err != nil {
				t.Log("mockServer() : Unable to read file", err)
			}
			_, err = w.Write(allTraits)
			if err != nil {
				t.Log("test/test_utility:mockServer(): Unable to write data")
			}
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
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

//SetupMockK8sConfiguration setting up mock k8s configurations
func SetupMockK8sConfiguration(t *testing.T, serverUrl string) *config.Configuration {

	temp, _ := ioutil.TempFile("", "config.yml")
	defer func() {
		derr := os.Remove(temp.Name())
		if derr != nil {
			log.WithError(derr).Errorf("Error removing file")
		}
	}()
	c, _ := config.LoadConfiguration()
	c.AASApiUrl = serverUrl + "/aas"
	c.IHUB.Username = "admin@hub"
	c.IHUB.Password = "hubAdminPass"
	c.AttestationService.HVSBaseURL = serverUrl + "/mtwilson/v2/"
	c.AttestationService.SHVSBaseURL = serverUrl + "/sgx-hvs/v2/"
	c.Endpoint.Type = "KUBERNETES"
	c.Endpoint.URL = serverUrl + "/"
	c.Endpoint.CRDName = "custom-isecl"
	c.Endpoint.CertFile = K8scertFilePath
	c.Endpoint.Token = K8sToken

	return c
}

//SetupMockOpenStackConfiguration setting up mock opentstack configurations
func SetupMockOpenStackConfiguration(t *testing.T, serverUrl string) *config.Configuration {

	temp, _ := ioutil.TempFile("", "config.yml")
	defer func() {
		derr := os.Remove(temp.Name())
		if derr != nil {
			log.WithError(derr).Errorf("Error removing file")
		}
	}()
	c, _ := config.LoadConfiguration()
	c.AASApiUrl = serverUrl + "/aas"
	c.IHUB.Username = "admin@hub"
	c.IHUB.Password = "hubAdminPass"
	c.Endpoint.Type = "OPENSTACK"
	c.Endpoint.AuthURL = serverUrl + "/v3/auth/tokens"
	c.Endpoint.URL = serverUrl + "/"
	c.Endpoint.UserName = OpenstackUserName
	c.Endpoint.Password = OpenstackPassword

	return c
}
