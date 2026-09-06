# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-FileCopyrightText: 2026 Nikolay Govorov
# SPDX-License-Identifier: AGPL-3.0-or-later

ARG ALPINE_VERSION=3.23.5
ARG ALPINE_DIGEST=sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
ARG DISTROLESS_DIGEST=sha256:a77defd6fedbb3392b175ba8ea3d1c22be963c1597c248c3ba987ddd80bfb512

FROM --platform=$BUILDPLATFORM docker.io/library/alpine:${ALPINE_VERSION}@${ALPINE_DIGEST} AS rootfs
RUN install -d -m 0750 /rootfs/var/lib/tesor

FROM gcr.io/distroless/cc-debian13:nonroot@${DISTROLESS_DIGEST}

ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="Tesor" \
      org.opencontainers.image.description="Tiny packages caching proxy" \
      org.opencontainers.image.source="https://git.dimidiumlabs.io/tesor" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

COPY --chown=root:root --chmod=0755 .container/binary-${TARGETARCH}/tesor /usr/local/bin/tesor
COPY --from=rootfs --chown=10000:10000 /rootfs/var/lib/tesor /var/lib/tesor
COPY --chown=root:root deploy/tesor.toml /etc/tesor.toml
COPY --chown=root:root LICENSE README.md /usr/share/doc/tesor/

USER 10000:10000
EXPOSE 2025
VOLUME ["/var/lib/tesor"]

ENTRYPOINT ["/usr/local/bin/tesor"]
CMD ["--config=/etc/tesor.toml"]
