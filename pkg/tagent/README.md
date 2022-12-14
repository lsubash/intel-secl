# ISecL Go Trust Agent (GTA)
The Trust Agent resides on physical servers and enables both remote attestation and the extended chain of trust capabilities. The Trust Agent maintains ownership of the server's Trusted Platform Module, allowing secure attestation quotes to be sent to the Verification Service.

## Key features
- Provides host specific information
- Provides secure attestation quotes
- RESTful APIs for easy and versatile access to above features

## System Requirements
- RHEL 8.4 or ubuntu 20.04
- TPM 2.0 device
- Packages
    - tpm2-tss (v2.0.x)
    - dmidecode (v3.x)
    - redhat-lsb-core (v4.1.x)
    - tboot (v1.9.7.x)
    - compat-openssl10 (v1.0.x)
- Proxy settings if applicable

*See [docs/install.md](doc/INSTALL.md) for additional installation instructions.*

## Software requirements
- git
- go version `1.18.8`

### Additional software requirements for building GTA container image in oci format
- docker
- skopeo

# Build Instructions
GTA use the `tpm-provider` library to access the TPM 2.0 device.  The following instructions assume that `gta-devel` docker image and container have been created as described in the 'Build Instructions' section of the `tpm-provider` project (see the README.md in that project for more details).

1. `make tagent-installer`
2. `tagent-v*.bin` will be present in the `deployments/installer/` path

Note: The `gta-devel` docker container can be used in this fashion to build GTA, but cannot be used to run or debug GTA because `tpm2-abrmd` must run as a service under `systemd`.  See `Unit Testing and TPM Simulator` in the `tpm-provider` project for instructions to run `systemd`, `tpm2-abrmd` and the TPM simulator in the `gta-devel` container.

# Build Instructions for container image

1. `make tagent-oci-archive`
2. `tagent-<version>-<commit-version>.tar` will be in the `deployments/containers/oci/` subdirectory

# Links
- [Installation instructions](doc/INSTALL.md)
- [GTA LLD](doc/LLD.md)
