TEMPLATE_REL_VERSION := v5.0.0

wls-db:
	rm -rf out && mkdir -p out
	cd src/wls && go build -ldflags "-X main.BuildVersion=$(TEMPLATE_REL_VERSION)" -o $(TEMPLATE_REL_VERSION)_wls_image_table_changes && mv $(TEMPLATE_REL_VERSION)_wls_image_table_changes ../../out
	$ echo "upgrades/wls/db/out/$(TEMPLATE_REL_VERSION)_wls_image_table_changes successfully created"

all: wls-db
