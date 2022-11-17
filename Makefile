SHELL := /bin/bash
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := v5.0.0
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
else
	undefine DOCKER_PROXY_FLAGS
endif

TARGETS = cms kbs ihub hvs authservice wpm wls tagent wlagent
K8S_EXTENSIONS_TARGETS = admission-controller isecl-k8s-controller isecl-k8s-scheduler
K8S_TARGETS = cms kbs ihub hvs authservice aas-manager wls tagent wlagent $(K8S_EXTENSIONS_TARGETS)

$(TARGETS):
	cd cmd/$@ && env GOOS=linux GOSUMDB=off go mod tidy && env GOOS=linux GOSUMDB=off  \
		go build -ldflags "-X github.com/intel-secl/intel-secl/v5/pkg/$@/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.GitHash=$(GITCOMMIT)" -o $@

tagent:
	cd cmd/$@ && env GOOS=linux GOSUMDB=off && env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW="-f.*"  \
		go build -mod=vendor -ldflags "-X github.com/intel-secl/intel-secl/v5/pkg/$@/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.GitHash=$(GITCOMMIT)" -o $@

wlagent:
	cd cmd/wlagent && env GOOS=linux GOSUMDB=off go mod tidy && env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW="-f.*"  \
		go build -ldflags "-extldflags=-Wl,--allow-multiple-definition -X github.com/intel-secl/intel-secl/v5/pkg/wlagent/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v5/pkg/wlagent/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v5/pkg/wlagent/version.GitHash=$(GITCOMMIT)" -o wlagent

$(K8S_EXTENSIONS_TARGETS):
	cd cmd/isecl-k8s-extensions/$@ && env GOOS=linux GOSUMDB=off go mod tidy && env GOOS=linux GOSUMDB=off \
		go build -ldflags "-X github.com/intel-secl/intel-secl/v5/pkg/$@/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.GitHash=$(GITCOMMIT)" -o $@

config-upgrade-binary:
	cd pkg/lib/common/upgrades && env GOOS=linux GOSUMDB=off go mod tidy && env GOOS=linux GOSUMDB=off go build -o config-upgrade

%-pre-installer: % config-upgrade-binary
	mkdir -p installer
	cp -r build/linux/$*/* installer/
	cp pkg/lib/common/upgrades/config-upgrade installer/
	cp pkg/lib/common/upgrades/*.sh installer/
	cp -a upgrades/manifest/ installer/
	cp -a upgrades/$*/* installer/
	if [ -d "./installer/db" ]; then \
		 rm -rf ./installer/db ;\
		 cd ./upgrades/$*/db && make all && cd - ;\
		 mkdir -p ./installer/database && cp -a ./upgrades/$*/db/out/* ./installer/database/ ;\
	fi
	mv installer/build/* installer/
	chmod +x installer/*.sh
	cp cmd/$*/$* installer/$*

%-installer: %-pre-installer %
	makeself installer deployments/installer/$*-$(VERSION).bin "$* $(VERSION)" ./install.sh
	rm -rf installer

tagent-pre-installer: tagent config-upgrade-binary
	mkdir -p installer
	cp -r build/linux/tagent/* installer/
	cp pkg/lib/common/upgrades/config-upgrade installer/
	cp pkg/lib/common/upgrades/*.sh installer/
	cp -a upgrades/manifest/ installer/
	cp -a upgrades/tagent/* installer/

	$(MAKE) -C pkg/tagent/tboot-xm package
	cp pkg/tagent/tboot-xm/out/application-agent*.bin installer/

	mv installer/build/* installer/
	chmod +x installer/*.sh
	cp cmd/tagent/tagent installer/tagent

tagent-installer: tagent-pre-installer
	makeself installer deployments/installer/trustagent-$(VERSION).bin "TrustAgent $(VERSION)" ./install.sh
	rm -rf installer

wlagent-installer: wlagent-pre-installer
	makeself installer deployments/installer/workload-agent-$(VERSION).bin "Workload Agent $(VERSION)" ./install.sh
	rm -rf installer

isecl-k8s-extensions-pre-installer: $(patsubst %, %-oci-archive, $(K8S_EXTENSIONS_TARGETS))

isecl-k8s-extensions-installer: isecl-k8s-extensions-pre-installer
	mkdir -p installer/isecl-k8s-extensions/yamls
	cp -r pkg/isecl-k8s-extensions/certificate-generation-scripts/* installer/isecl-k8s-extensions/
	cp deployments/container-archive/oci/isecl-k8s-scheduler*.tar installer/isecl-k8s-extensions/
	cp deployments/container-archive/oci/isecl-k8s-controller*.tar installer/isecl-k8s-extensions/
	cp deployments/container-archive/oci/admission-controller*.tar installer/isecl-k8s-extensions/
	cp -r build/linux/isecl-k8s-extensions/config-files/* installer/isecl-k8s-extensions/
	cd installer/ && tar -zcvf isecl-k8s-extensions-$(VERSION).tar.gz isecl-k8s-extensions

%-docker: %
	docker build ${DOCKER_PROXY_FLAGS} --label org.label-schema.build-date=$(BUILDDATE) -f build/image/$*/Dockerfile -t $(DOCKER_REGISTRY)isecl/$*:$(VERSION)-$(GITCOMMIT) .

hvs-docker: hvs
	cd ./upgrades/hvs/db && make all && cd -
	docker build ${DOCKER_PROXY_FLAGS} --label org.label-schema.build-date=$(BUILDDATE) -f build/image/hvs/Dockerfile -t $(DOCKER_REGISTRY)isecl/hvs:$(VERSION)-$(GITCOMMIT) .

tagent-docker: tagent config-upgrade-binary
	docker build ${DOCKER_PROXY_FLAGS} --label org.label-schema.build-date=$(BUILDDATE) -f build/image/tagent/Dockerfile -t $(DOCKER_REGISTRY)isecl/tagent:$(VERSION)-$(GITCOMMIT) .

%-docker-push: %-docker
	docker tag $(DOCKER_REGISTRY)isecl/$*:$(VERSION)-$(GITCOMMIT) $(DOCKER_REGISTRY)isecl/$*:$(VERSION)
	docker push $(DOCKER_REGISTRY)isecl/$*:$(VERSION)
	docker push $(DOCKER_REGISTRY)isecl/$*:$(VERSION)-$(GITCOMMIT)

%-swagger:
	env GOOS=linux GOSUMDB=off go mod tidy
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/$* -o ./docs/swagger/$*-openapi.yml
	swagger validate ./docs/swagger/$*-openapi.yml

installer: clean $(patsubst %, %-installer, $(TARGETS)) aas-manager isecl-k8s-extensions-installer

docker: $(patsubst %, %-docker, $(K8S_TARGETS))

%-oci-archive: %-docker
	skopeo copy docker-daemon:isecl/$*:$(VERSION)-$(GITCOMMIT) oci-archive:deployments/container-archive/oci/$*-$(VERSION)-$(GITCOMMIT).tar:$(VERSION)

populate-users:
	cd tools/aas-manager && env GOOS=linux GOSUMDB=off go build -o populate-users

aas-manager: populate-users
	cp tools/aas-manager/populate-users deployments/installer/populate-users.sh
	cp build/linux/authservice/install_pgdb.sh deployments/installer/install_pgdb.sh
	cp build/linux/authservice/create_db.sh deployments/installer/create_db.sh
	chmod +x deployments/installer/install_pgdb.sh
	chmod +x deployments/installer/create_db.sh

download-eca:
	rm -rf build/linux/hvs/external-eca.pem
	mkdir -p certs/
	wget https://download.microsoft.com/download/D/6/5/D65270B2-EAFD-43FD-B9BA-F65CA00B153E/TrustedTpm.cab -O certs/TrustedTpm.cab
	cabextract certs/TrustedTpm.cab -d certs
	wget https://tsci.intel.com/content/OnDieCA/certs/TGL_00002003_OnDie_CA.cer -O certs/TGL_00002003_OnDie_CA.cer
	find certs/ \( -name '*.der' -or -name '*.crt' -or -name '*.cer' \) | sed 's| |\\ |g' | xargs -L1 openssl x509 -inform DER -outform PEM -in >> build/linux/hvs/external-eca.pem 2> /dev/null || true
	rm -rf certs

test:
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off go mod tidy
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off go build github.com/intel-secl/pkg/tagent/...
	env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

k8s: $(patsubst %, %-k8s, $(K8S_TARGETS))

%-k8s:  %-oci-archive
	cp tools/download-tls-certs.sh deployments/k8s/

authservice-k8s: authservice-oci-archive aas-manager

all: clean installer test k8s

clean:
	rm -f cover.*
	rm -rf deployments/installer/*.bin
	rm -rf deployments/container-archive/docker/*.tar
	rm -rf deployments/container-archive/oci/*.tar

.PHONY: installer test all clean aas-manager kbs
