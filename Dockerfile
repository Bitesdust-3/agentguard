FROM golang:1.27-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=1 go build -mod=vendor -trimpath -ldflags="-s -w -X main.version=v1.0.0" -o /out/agentguard ./cmd/agentguard && \
    CGO_ENABLED=1 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/benchmark ./cmd/benchmark

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    install -d -o 65532 -g 65532 /app/data /app/configs /app/tests/benchmark

WORKDIR /app
COPY --from=builder --chown=65532:65532 /out/agentguard /out/benchmark ./
COPY --chown=65532:65532 configs/config.docker.yaml ./configs/config.docker.yaml
COPY --chown=65532:65532 tests/benchmark ./tests/benchmark

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/agentguard"]
CMD ["-config", "/app/configs/config.docker.yaml"]
