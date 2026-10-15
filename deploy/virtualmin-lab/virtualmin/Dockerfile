# syntax=docker/dockerfile:1
#
# Vanilla Virtualmin GPL node: Debian 12 slim + systemd (PID 1) + OpenSSH +
# the package set the official installer selects for `--minimal --bundle LAMP`.
#
# Installer phase 3 (repository + packages) runs here, at build time, with the
# repository signing keys verified by fingerprint and every Virtualmin-owned
# package pinned. Installer phase 4 (`virtualmin-config-system`) needs running
# services, so it runs once at first boot (virtualmin-lab-firstboot.service).
#
# No credentials, host keys, TLS keys or machine identity live in any layer:
# they are generated or injected at boot. See ../README.md.

ARG DEBIAN_IMAGE=debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
FROM ${DEBIAN_IMAGE}
ARG DEBIAN_IMAGE

ARG VIRTUALMIN_REPO=https://download.virtualmin.com
ARG VIRTUALMIN_KEY_SERVER=https://keyserve.virtualmin.com
# Primary key fingerprints of "Virtualmin Developers" and its Sentinel key.
ARG VIRTUALMIN_KEY_FINGERPRINTS="A37DB2F5499365669717F15173FE86789906C8C9 F103C1A32EA75BF911C33707ECEDBFD252CAC4B4"
ARG WEBMIN_VERSION=2.670
ARG VIRTUAL_SERVER_VERSION=8.3.0-1-gpl
ARG VIRTUALMIN_CORE_VERSION=8.2.0-1
ARG VIRTUALMIN_CONFIG_VERSION=8.3.0-1
ARG VIRTUALMIN_STACK_VERSION=8.2.0-1
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="virtualmin-lab" \
      org.opencontainers.image.description="Vanilla Virtualmin GPL (minimal LAMP) on Debian 12 with systemd and OpenSSH, for integration testing" \
      org.opencontainers.image.source="https://github.com/captainpragmatic/PRAHO" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VIRTUAL_SERVER_VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.base.name="${DEBIAN_IMAGE}" \
      io.virtualmin.webmin.version="${WEBMIN_VERSION}" \
      io.virtualmin.virtual-server.version="${VIRTUAL_SERVER_VERSION}" \
      io.virtualmin.core.version="${VIRTUALMIN_CORE_VERSION}" \
      io.virtualmin.config.version="${VIRTUALMIN_CONFIG_VERSION}" \
      io.virtualmin.stack.version="${VIRTUALMIN_STACK_VERSION}"

ENV container=docker \
    LANG=C.UTF-8

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Base: systemd as PID 1 and OpenSSH. No service may start during the build.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server ca-certificates curl gpg \
 && rm -rf /var/lib/apt/lists/*

# Virtualmin repository, signing keys verified by exact fingerprint set.
RUN keydir="$(mktemp -d)" \
 && for key in virtualmin-developers-default-rsa.pub.asc virtualmin-developers-sentinel-rsa.pub.asc; do \
      curl -fsSL --proto '=https' --tlsv1.2 -o "${keydir}/${key}" "${VIRTUALMIN_KEY_SERVER}/${key}"; \
    done \
 && cat "${keydir}"/*.asc | gpg --dearmor > /usr/share/keyrings/debian-virtualmin-developers.gpg \
 && actual="$(gpg --show-keys --with-colons /usr/share/keyrings/debian-virtualmin-developers.gpg \
      | awk -F: '$1 == "pub" { want = 1; next } $1 == "fpr" && want { print $10; want = 0 }' \
      | sort | tr '\n' ' ' | sed 's/ $//')" \
 && expected="$(printf '%s\n' ${VIRTUALMIN_KEY_FINGERPRINTS} | sort | tr '\n' ' ' | sed 's/ $//')" \
 && if [ "${actual}" != "${expected}" ]; then \
      echo "Virtualmin signing key fingerprint mismatch: got [${actual}] want [${expected}]" >&2; exit 1; \
    fi \
 && rm -rf "${keydir}" \
 && echo "deb [signed-by=/usr/share/keyrings/debian-virtualmin-developers.gpg] ${VIRTUALMIN_REPO} virtualmin main" \
      > /etc/apt/sources.list.d/virtualmin-stable.list

# An empty version argument installs the repository's latest package of that name: the nightly drift check
# (`VIRTUALMIN_LAB_UNPINNED=1 lab.sh build`) builds that way. webmin-virtual-server is the exception: its version
# argument is the glob `*-gpl`, because the repository also carries a licensed `-pro` build with a higher version. The pinned build expands to exactly `name=version`.
#
# Installer phase 3, exactly as virtualmin-install.sh runs it for
# `--minimal --bundle LAMP`: webmin first, then virtualmin-core plus the
# minimal LAMP stack, with recommends.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --install-recommends \
      -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
      "webmin${WEBMIN_VERSION:+=${WEBMIN_VERSION}}" \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --install-recommends \
      -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
      "webmin-virtual-server${VIRTUAL_SERVER_VERSION:+=${VIRTUAL_SERVER_VERSION}}" \
      "virtualmin-core${VIRTUALMIN_CORE_VERSION:+=${VIRTUALMIN_CORE_VERSION}}" \
      "virtualmin-config${VIRTUALMIN_CONFIG_VERSION:+=${VIRTUALMIN_CONFIG_VERSION}}" \
      "virtualmin-lamp-stack-minimal${VIRTUALMIN_STACK_VERSION:+=${VIRTUALMIN_STACK_VERSION}}" \
 && apt-mark hold webmin webmin-virtual-server virtualmin-core virtualmin-config virtualmin-lamp-stack-minimal \
 && rm -rf /var/lib/apt/lists/*

# Per-container identity is regenerated at boot, never shipped in a layer.
RUN rm -f /usr/sbin/policy-rc.d \
      /etc/ssh/ssh_host_* \
      /etc/webmin/miniserv.pem /etc/webmin/miniserv.cert /etc/webmin/miniserv.key \
 && : > /etc/machine-id \
 && rm -f /var/lib/dbus/machine-id

# Build context is deploy/virtualmin-lab/ (shared boot units live in common/).
COPY common/rootfs/ /
COPY virtualmin/rootfs/ /

RUN chmod 0755 /usr/local/sbin/lab-node-* /usr/local/sbin/virtualmin-lab-* \
 && systemctl enable lab-node-identity.service lab-node-credentials.service \
      virtualmin-lab-firstboot.service ssh.service \
 && systemctl mask getty@tty1.service console-getty.service systemd-firstboot.service

EXPOSE 22 10000
STOPSIGNAL SIGRTMIN+3
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=90 \
  CMD ["/usr/local/sbin/virtualmin-lab-health"]
CMD ["/sbin/init"]
