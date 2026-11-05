FROM ubuntu:26.04 AS runtime
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv openssh-server openssh-client python3 python3-apt sudo ufw iproute2 \
    curl ca-certificates gnupg git build-essential locales gettext dnsmasq-base unzip util-linux-extra \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && ssh-keygen -A && systemctl enable ssh.socket
RUN curl --fail --silent --show-error --location https://astral.sh/uv/install.sh -o /tmp/uv-install \
    && UV_INSTALL_DIR=/usr/local/bin sh /tmp/uv-install && rm /tmp/uv-install
ENV UV_PYTHON_INSTALL_DIR=/opt/praho-python UV_PYTHON_BIN_DIR=/opt/praho-python/bin
RUN uv python install 3.13
COPY pyproject.toml uv.lock /fixture-dependencies/
COPY services/platform/pyproject.toml /fixture-dependencies/services/platform/pyproject.toml
COPY services/portal/pyproject.toml /fixture-dependencies/services/portal/pyproject.toml
ENV UV_CACHE_DIR=/var/cache/praho-uv
WORKDIR /
RUN truncate -s 0 /etc/machine-id && rm -f /var/lib/dbus/machine-id
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

FROM runtime AS controller
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rsync \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN uv venv --python 3.13 /opt/controller \
    && uv pip install --python /opt/controller/bin/python ansible-core==2.20.6 \
    && /opt/controller/bin/ansible-galaxy collection install \
       ansible.posix:2.2.0 community.general:12.6.1 community.postgresql:4.2.0

FROM runtime AS platform
WORKDIR /fixture-dependencies
RUN uv sync --frozen --group platform --group portal --group prod --no-dev --no-install-workspace --no-install-project \
    && rm -rf .venv && chmod -R a+rX /var/cache/praho-uv /opt/praho-python
WORKDIR /

FROM runtime AS portal
WORKDIR /fixture-dependencies
RUN uv sync --frozen --group portal --group prod --no-dev --no-install-workspace --no-install-project \
    && rm -rf .venv && chmod -R a+rX /var/cache/praho-uv /opt/praho-python
WORKDIR /
