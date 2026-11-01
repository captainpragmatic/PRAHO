# syntax=docker/dockerfile:1
# Opt-in imported source: the pinned native stack plus real mail and DNS services.
ARG VIRTUALMIN_LAB_BASE_IMAGE=praho-virtualmin-lab:8.3.0
FROM ${VIRTUALMIN_LAB_BASE_IMAGE}
ARG VIRTUALMIN_SOURCE_STACK_VERSION=8.2.0-1

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Service identity and credentials are still generated/injected at container boot.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --install-recommends \
      "virtualmin-lamp-stack=${VIRTUALMIN_SOURCE_STACK_VERSION}" bind9-dnsutils \
 && rm -f /usr/sbin/policy-rc.d \
 && rm -f /etc/usermin/miniserv.pem \
 && rm -rf /var/lib/apt/lists/*

COPY mixed-source/rootfs/ /
RUN chmod 0755 /usr/local/sbin/virtualmin-lab-mixed-* \
 && systemctl enable virtualmin-lab-mixed-source.service

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=90 \
  CMD ["/usr/local/sbin/virtualmin-lab-mixed-health"]
