# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

LABEL org.label-schema.name="Trustagent Agent" \
    org.label-schema.vendor="Intel Corporation" \
    org.label-schema.license="BSD-3-Clause" \
    org.label-schema.url="https://github.com/intel-secl/intel-secl"

RUN yum install -y tpm2-tss && \
    rm -rf /var/cache /var/log/dnf* /var/log/yum.* && \
    mkdir -p /opt/trustagent/var/system-info/ /opt/trustagent/var/ramfs /var/log/trustagent /config/
COPY cmd/tagent/tagent  /usr/bin/tagent
COPY build/image/tagent/entrypoint.sh /entrypoint.sh
RUN touch /.container-env && chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
