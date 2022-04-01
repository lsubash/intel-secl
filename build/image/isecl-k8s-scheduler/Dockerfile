#/*
# * Copyright (C) 2020 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

FROM ubuntu:focal

COPY cmd/isecl-k8s-extensions/isecl-k8s-scheduler/isecl-k8s-scheduler /usr/bin/isecl-k8s-scheduler
RUN touch /.container-env && chmod +x /usr/bin/isecl-k8s-scheduler && mkdir -p /var/log/isecl-k8s-scheduler

ENTRYPOINT ["/usr/bin/isecl-k8s-scheduler"]

