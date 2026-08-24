# ---- build stage ----
FROM golang:1.23-alpine AS build

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
# Build a static, stripped binary.
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/dockgate ./cmd/dockgate

# ---- runtime stage ----
FROM alpine:3.20

RUN addgroup -S dockgate && adduser -S -G dockgate dockgate

COPY --from=build /out/dockgate /usr/local/bin/dockgate
COPY policy.yaml /etc/dockgate/policy.yaml

# DockGate itself needs no root; it only needs read/write access to the mounted
# Docker socket. Grant that at runtime (e.g. --group-add for the docker gid).
USER dockgate

EXPOSE 2375

ENTRYPOINT ["/usr/local/bin/dockgate"]
CMD ["--listen", "0.0.0.0:2375", "--policy", "/etc/dockgate/policy.yaml"]
