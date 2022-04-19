# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

LABEL org.label-schema.name="Trustagent Agent" \
    org.label-schema.vendor="Intel Corporation" \
    org.label-schema.license="BSD-3-Clause" \
    org.label-schema.url="https://github.com/intel-secl/intel-secl"

RUN apt-get update -y && apt-get install -y libtss2-esys0 && \
    apt-get clean && apt-get autoclean && \
    mkdir -p /opt/trustagent/var/system-info/ /opt/trustagent/var/ramfs /var/log/trustagent /config/
COPY cmd/tagent/tagent  /usr/bin/tagent

COPY build/image/tagent/entrypoint.sh /entrypoint.sh

COPY upgrades/tagent/config/* /config/

COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh

COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh

COPY pkg/lib/common/upgrades/config-upgrade /config-upgrade

RUN touch /.container-env && chmod +x -R /entrypoint.sh /container_upgrade.sh /config_upgrade.sh /config /config-upgrade

CMD ["/entrypoint.sh"]
