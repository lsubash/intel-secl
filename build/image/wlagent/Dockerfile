#Copyright (C) 2019 Intel Corporation
#SPDX-License-Identifier: BSD-3-Clause
 
FROM ubuntu:focal

LABEL org.label-schema.name="Workload Agent" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

COPY cmd/wlagent/wlagent /usr/bin/
COPY build/image/wlagent/entrypoint.sh /entrypoint.sh

#Copy upgrade scripts
COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh
COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh
COPY upgrades/wlagent/config/* /config/

RUN apt-get update -y && apt-get install -y libtss2-dev dmidecode && \
    apt-get clean && apt-get autoclean  && \
    chmod -R +x /container_upgrade.sh /config_upgrade.sh /config /entrypoint.sh && touch /.container-env

CMD ["/entrypoint.sh"]
