#/*
# * Copyright (C) 2021 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

FROM centos:8

COPY cmd/isecl-k8s-extensions/admission-controller/admission-controller /usr/bin/admission-controller

ENTRYPOINT ["/usr/bin/admission-controller"]
