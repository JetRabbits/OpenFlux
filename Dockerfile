# syntax=docker/dockerfile:1

FROM --platform=$TARGETPLATFORM golang:1.25-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

ENV GOTOOLCHAIN=auto

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w -checklinkname=0" \
      -o /out/openflux \
      .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/openflux /usr/local/bin/openflux

ENTRYPOINT ["/usr/local/bin/openflux"]
