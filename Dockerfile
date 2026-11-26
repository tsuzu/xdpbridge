# SPDX-License-Identifier: Apache-2.0
FROM golang:1.23.4-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev gcc \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=v0.1.0-dev
RUN make build VERSION=${VERSION}

FROM gcr.io/distroless/static-debian12
COPY --from=build /src/bin/xdpl2-daemon /src/bin/xdpl2-cni /usr/local/bin/
COPY LICENSE /usr/share/doc/xdpl2/LICENSE
ENTRYPOINT ["/usr/local/bin/xdpl2-daemon"]
