ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 php-fpm libfcgi-bin curl util-linux passwd procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/bin/sleep", "300"]
