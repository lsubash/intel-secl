module github.com/intel-secl/intel-secl/v5

require (
	github.com/DATA-DOG/go-sqlmock v1.4.1
	github.com/Waterdrips/jwt-go v3.2.1-0.20200915121943-f6506928b72e+incompatible
	github.com/antchfx/jsonquery v1.1.4
	github.com/beevik/etree v1.1.0
	github.com/cloudflare/cfssl v1.5.0
	github.com/containers/ocicrypt v1.1.2
	github.com/davecgh/go-spew v1.1.1
	github.com/gemalto/kmip-go v0.0.6-0.20210426170211-84e83580888d
	github.com/gin-gonic/gin v1.7.4
	github.com/google/uuid v1.2.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/hashicorp/golang-lru v0.5.1
	github.com/jinzhu/copier v0.3.0
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/lib/pq v1.3.0
	github.com/mattermost/xml-roundtrip-validator v0.0.0-20201213122252-bcd7e1b9601e
	github.com/nats-io/jwt/v2 v2.2.1-0.20220330180145-442af02fd36a
	github.com/nats-io/nats.go v1.15.0
	github.com/nats-io/nkeys v0.3.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/ginkgo/v2 v2.1.3
	github.com/onsi/gomega v1.17.0
	github.com/pkg/errors v0.9.1
	github.com/russellhaering/goxmldsig v1.1.1-0.20210828032938-dfbd95396ace
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/vmware/govmomi v0.22.2
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/grpc v1.38.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.22.4
	k8s.io/apimachinery v0.22.4
	k8s.io/client-go v0.22.4
	k8s.io/kube-scheduler v0.22.4
)

replace github.com/vmware/govmomi => github.com/arijit8972/govmomi fix-tpm-attestation-output