#/*
# * Copyright (C) 2020 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

FROM ubuntu:focal

RUN apt-get update -y && apt-get install -y curl && apt-get clean && apt-get autoclean && \
    curl -LO https://storage.googleapis.com/kubernetes-release/release/`\
    curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl && \
    chmod +x kubectl && mkdir -p /var/log/isecl-k8s-extensions 

COPY cmd/isecl-k8s-extensions/isecl-k8s-controller/isecl-k8s-controller /usr/bin/isecl-k8s-controller
RUN touch /.container-env && chmod +x /usr/bin/isecl-k8s-controller

ENTRYPOINT ["/usr/bin/isecl-k8s-controller"]
