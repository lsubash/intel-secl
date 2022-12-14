# Certificate Management Service

`Certificate Management Service` is a web service whose purpose is to manage all Certificates in ecosystem

## Key features
- Provides self signed Root CA
- Sign rest of the certificates in ecosystem by Root CA
- RESTful APIs for easy and versatile access to above features

## Build Certificate Management service

- Git clone the Certificate Management service
- Run scripts to build the Certificate Management service

```shell
git clone https://github.com/intel-secl/intel-secl.git
cd intel-secl
make cms-installer
```

### Deploy
```console
> ./cms-*.bin
```

OR

```console
> docker-compose -f dist/docker/docker-compose.yml up
```

### Manage service
* Start service
    * cms start
* Stop service
    * cms stop
* Status of service
    * cms status

# Third Party Dependencies

## Certificate Management Service

### Direct dependencies

| Name        | Repo URL                    | Minimum Version Required           |
| ----------- | --------------------------- | :--------------------------------: |
| uuid        | github.com/google/uuid      | v1.2.0                             |
| handlers    | github.com/gorilla/handlers | v1.4.2                             |
| mux         | github.com/gorilla/mux      | v1.7.4                             |
| gorm        | github.com/jinzhu/gorm      | v1.9.16                            |
| logrus      | github.com/sirupsen/logrus  | v1.7.0                             |
| testify     | github.com/stretchr/testify | v1.6.1                             |
| crypto      | golang.org/x/crypto         | v0.0.0-20190219172222-a4c6cb3142f2 |
| yaml.v3     | gopkg.in/yaml.v3            | v3.0.1                             |
| authservice | intel/isecl/authservice     | v5.0.0	                         |
| common      | intel/isecl/lib/common      | v5.0.0                             |

### Indirect Dependencies

| Repo URL                     | Minimum version required           |
| -----------------------------| :--------------------------------: |
| github.com/jinzhu/inflection | v0.0.0-20180308033659-04140366298a |
| github.com/lib/pq            | v1.0.0                             |

*Note: All dependencies are listed in go.mod*

