#/*
# * Copyright (C) 2020 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

FROM centos:8

RUN yum -yq install curl && \
    curl -LO https://storage.googleapis.com/kubernetes-release/release/`\
    curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl && \
    chmod +x kubectl && mkdir -p /var/log/isecl-k8s-extensions && \
    rm -rf /var/cache /var/log/dnf* /var/log/yum.*
COPY cmd/isecl-k8s-extensions/isecl-k8s-controller/isecl-k8s-controller /usr/bin/isecl-k8s-controller
RUN touch /.container-env && chmod +x /usr/bin/isecl-k8s-controller

ENTRYPOINT ["/usr/bin/isecl-k8s-controller"]
