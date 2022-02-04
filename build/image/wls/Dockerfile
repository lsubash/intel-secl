#  Copyright (C) 2021 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

RUN mkdir -p /opt/wls/bin

LABEL org.label-schema.name="Workload Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

COPY cmd/wls/wls  /usr/bin/wls

COPY build/image/wls/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
