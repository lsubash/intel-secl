# Intel<sup>®</sup> Security Libraries for Data Center - Application Agent

#### The `Application Agent` resides on physical servers and extends the chain of trust to applications installed on server.

## Key features

- Extends TPM PCRs with application measurements
- Provides event log for application measurements
- Facilitates attestation for installed applications

## System Requirements

- RHEL 8.x
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements

- git
- make

# Step By Step Build Instructions

## Install required shell commands

Please make sure that you have the right `http proxy` settings if you are behind a proxy

```shell
export HTTP_PROXY=http://<proxy>:<port>
export HTTPS_PROXY=https://<proxy>:<port>
```

### Install tools from `yum`

```shell
$ sudo yum install -y wget git zip unzip ant gcc patch gcc-c++ openssl-devel makeself
```

