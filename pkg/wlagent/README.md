# Workload Agent

`Workload Agent` is used to launch encrypted workloads on a trusted host.

## Key features

- Create container trust report
- Fetch a flavor from Workload Service

## System Requirements

- RHEL 8.4 or ubuntu 20.04
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements

- git
- makeself
- `go` version 1.18.8
- docker 18.06 or higher

### Additional software requirements for building GTA container image in oci format

- skopeo

## Step-By-Step Build Instructions

## Install required shell commands

### Install tools from `yum`

```shell
sudo yum install -y git wget makeself
```

### Install `go` version 1.18.8

The `Workload Agent` requires Go version 1.18.8 that has support for `go modules`. The build was validated with the
latest version go1.18.8 of `go`. It is recommended that you use go1.18.8 version of `go`. You can use the following to
install `go`.

```shell
wget https://dl.google.com/go/go1.18.8.linux-amd64.tar.gz
tar -xzf go1.18.8.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Workload Agent(WLA)

### Build full installer

Supports the following use cases:

- Container confidentiality using skopeo and cri-o

```shell
make wlagent-installer
```

# Build Instructions for container image

1. `make wlagent-oci-archive`
3. `wlagent-<version>-<commit-version>.tar` will be in the deployments/container-archive/oci/out subdirectory

# Third Party Dependencies

*Note: All dependencies are listed in go.mod*

# Links

https://intel-secl.github.io/docs/