# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

FROM golang:1.25-alpine AS build

# VERSION is stamped into main.Version of the binary at link time.
# Override with `docker build --build-arg VERSION=v1.2.3 ...`; the
# Makefile passes $(TAG) here on `make build-image`.
ARG VERSION=dev
ENV VERSION=$VERSION

# Build context is the parent directory (WIP/) — the Makefile invokes
# `docker build -f outrelay-relay/Dockerfile ..` so this Dockerfile
# can see the OutRelay sibling module referenced by the local
# `replace` directive in go.mod.
WORKDIR /src

COPY OutRelay       /src/OutRelay
COPY outrelay-relay /src/outrelay-relay

WORKDIR /src/outrelay-relay

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/outrelay-relay ./cmd/outrelay-relay

FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/outrelay-relay /usr/local/bin/

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/outrelay-relay"]
