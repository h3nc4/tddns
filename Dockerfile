# Copyright (C) 2026  Henrique Almeida
# This file is part of tddns.
#
# tddns is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# tddns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with tddns.  If not, see <https://www.gnu.org/licenses/>.

################################################################################
# A Dockerfile to build a runtime container for tddns.
ARG RUNTIME_GID_UID=65534:65534

########################################
# Build stage
FROM alpine:3.23 AS builder
ARG RUNTIME_GID_UID

# Install build dependencies
RUN apk add --no-cache \
  build-base \
  curl-dev \
  curl-static \
  openssl-dev \
  openssl-libs-static \
  zlib-static \
  brotli-static \
  zstd-static \
  nghttp2-static \
  nghttp3-static \
  libpsl-static \
  libidn2-static \
  libunistring-static

# Copy source code
WORKDIR /src
COPY tddns.c Makefile /src/

# Build static binary
RUN make STATIC=1 && strip --strip-all tddns

# Prepare rootfs for scratch
RUN mkdir -p /rootfs/etc/ssl/certs /rootfs/var/run && \
  cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ && \
  cp /src/tddns /rootfs/tddns && \
  chown -R "${RUNTIME_GID_UID}" /rootfs

########################################
# Runtime stage
FROM scratch AS final
ARG RUNTIME_GID_UID

COPY --from=builder /rootfs/ /

USER ${RUNTIME_GID_UID}

ENTRYPOINT ["/tddns"]

LABEL org.opencontainers.image.title="tddns" \
  org.opencontainers.image.description="A Tiny DDNS daemon for Cloudflare" \
  org.opencontainers.image.authors="Henrique Almeida <me@h3nc4.com>" \
  org.opencontainers.image.vendor="Henrique Almeida" \
  org.opencontainers.image.licenses="AGPL-3.0-or-later" \
  org.opencontainers.image.url="https://h3nc4.com" \
  org.opencontainers.image.source="https://github.com/h3nc4/tddns" \
  org.opencontainers.image.documentation="https://github.com/h3nc4/tddns/blob/main/README.md" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.revision="${COMMIT_SHA}" \
  org.opencontainers.image.created="${BUILD_DATE}" \
  org.opencontainers.image.ref.name="${VERSION}"
