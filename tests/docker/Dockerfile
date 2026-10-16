# SPDX-License-Identifier: MIT
# Isolated Maât integration testing ONLY. No installed host services are used.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
LABEL org.maat.e2e="true"

# Do not start package-installed services during image construction.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake make pkg-config autoconf automake libtool \
        libssl-dev zlib1g-dev libsqlite3-dev libcrypt-dev libzstd-dev \
        libapr1-dev libaprutil1-dev libpcre2-dev \
        apache2 apache2-dev libapache2-mod-php8.1 \
        php8.1-cli php8.1-dev php8.1-phpdbg \
        python3 curl perl openssl passwd util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# SSH logins and UID isolation exist solely inside this disposable image.
RUN useradd --system --no-create-home --shell /bin/false maatweb \
    && useradd --system --no-create-home --shell /usr/sbin/nologin maatsshd \
    && useradd --create-home --shell /bin/bash maatbuild \
    && mkdir -p /var/empty/maat /usr/lib/maat \
    && chmod 0755 /var/empty/maat \
    && touch /etc/maat-disposable-test-image \
    && chmod 0444 /etc/maat-disposable-test-image

# Prepare ownership before switching to the unprivileged build account.
# Rust installation must precede COPY so edits to Maât don't invalidate it.
WORKDIR /opt/maat
RUN install -d -m 0755 -o maatbuild -g maatbuild /opt/maat /opt/maat/build
USER maatbuild
# Ubuntu 22.04's packaged Rust toolchain is too old for the locked BBS crates.
# Install a pinned toolchain only inside the disposable build image.
ENV PATH="/home/maatbuild/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain 1.95.0
COPY --chown=maatbuild:maatbuild . /opt/maat/
# Catch ownership errors before starting the lengthy native toolchain build.
RUN test -w /opt/maat && test -w /opt/maat/build
# This runs compilation, 10 CTests, seven PHPTs, and real Apache smoke tests.
# No --privileged and no sudo. OpenSSH is built but not installed system-wide.
RUN ./build.sh --skip-vendored-apache

USER root
ENV MAAT_CONFIRM_DISPOSABLE_VM=yes
ENTRYPOINT ["/bin/bash", "/opt/maat/tests/docker/container-e2e.sh"]
