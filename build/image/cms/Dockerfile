#  Copyright (C) 2021 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

LABEL org.label-schema.name="Certificate Management Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

COPY cmd/cms/cms /usr/bin/cms

COPY build/image/cms/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh"]
