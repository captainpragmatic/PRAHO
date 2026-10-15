# syntax=docker/dockerfile:1
#
# Bare Debian 12 node: debian:12-slim + systemd (PID 1) + OpenSSH, nothing else.
# A clean target for exercising node provisioning playbooks from scratch.
# Host keys and machine id are generated at boot; credentials are injected
# through /etc/lab-node/inject (see ../README.md).

ARG DEBIAN_IMAGE=debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
FROM ${DEBIAN_IMAGE}
ARG DEBIAN_IMAGE

ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="debian-node" \
      org.opencontainers.image.description="Debian 12 slim with systemd and OpenSSH, for node provisioning tests" \
      org.opencontainers.image.source="https://github.com/captainpragmatic/PRAHO" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="12" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.base.name="${DEBIAN_IMAGE}"

ENV container=docker \
    LANG=C.UTF-8

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/sbin/policy-rc.d /etc/ssh/ssh_host_* /var/lib/dbus/machine-id \
 && : > /etc/machine-id

# Build context is deploy/virtualmin-lab/.
COPY common/rootfs/ /

RUN chmod 0755 /usr/local/sbin/lab-node-* \
 && systemctl enable lab-node-identity.service lab-node-credentials.service ssh.service \
 && systemctl mask getty@tty1.service console-getty.service systemd-firstboot.service

EXPOSE 22
STOPSIGNAL SIGRTMIN+3
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=24 \
  CMD ["/bin/systemctl", "is-active", "--quiet", "ssh.service"]
CMD ["/sbin/init"]
