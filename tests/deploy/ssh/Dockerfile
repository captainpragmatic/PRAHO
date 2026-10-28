ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv openssh-server python3 python3-apt python3-venv sudo ufw iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && ssh-keygen -A \
    && systemctl enable ssh.socket \
    && python3 -m venv /opt/controller \
    && /opt/controller/bin/pip install --no-cache-dir ansible-core==2.20.6 \
    && /opt/controller/bin/ansible-galaxy collection install ansible.posix:2.2.0 community.general:12.6.1
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
