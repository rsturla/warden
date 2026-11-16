FROM registry.access.redhat.com/hi/go:1.26 AS builder

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

FROM registry.access.redhat.com/hi/core-runtime:latest@sha256:81280d7fd6afa7a3d2a6da2e90e545cf8e5d187c80a69b2a1c875fdcd731aaed

COPY --from=builder /warden /usr/bin/warden
COPY --from=builder /warden-bridge /usr/bin/warden-bridge

ENTRYPOINT ["/usr/bin/warden"]
