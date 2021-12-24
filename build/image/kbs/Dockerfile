#  Copyright (C) 2021 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

LABEL org.label-schema.name="Key Broker Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

COPY cmd/kbs/kbs /usr/bin/kbs

COPY build/image/kbs/entrypoint.sh /entrypoint.sh

# Copy upgrade scripts
RUN mkdir -p /config

COPY upgrades/kbs/config/* /config/

COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh

COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh

RUN touch /.container-env && chmod -R +x /entrypoint.sh /container_upgrade.sh /config_upgrade.sh /config

RUN ln -sfT /usr/bin/kbs /kbs

ENTRYPOINT ["/entrypoint.sh"]
