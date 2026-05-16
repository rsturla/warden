FROM registry.access.redhat.com/hi/go:1.26@sha256:8ccab2865d1405c0c234deab78686033526e42270e8e51e3604ca6db7f6576dd AS builder

COPY . /src
WORKDIR /src

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN go build -trimpath \
    -ldflags="-s -w \
      -X github.com/rsturla/warden/internal/version.Version=${VERSION} \
      -X github.com/rsturla/warden/internal/version.Commit=${COMMIT} \
      -X github.com/rsturla/warden/internal/version.Date=${DATE}" \
    -o /warden ./cmd/warden && \
    go build -trimpath \
    -ldflags="-s -w \
      -X github.com/rsturla/warden/internal/version.Version=${VERSION} \
      -X github.com/rsturla/warden/internal/version.Commit=${COMMIT} \
      -X github.com/rsturla/warden/internal/version.Date=${DATE}" \
    -o /warden-bridge ./cmd/warden-bridge

FROM registry.access.redhat.com/hi/core-runtime:latest@sha256:8e26a551cf67278a00e1c9a007c09d7df60567b92f5ef57372a06fffbbb7b858

COPY --from=builder /warden /usr/bin/warden
COPY --from=builder /warden-bridge /usr/bin/warden-bridge

ENTRYPOINT ["/usr/bin/warden"]
