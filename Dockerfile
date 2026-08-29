# syntax=docker/dockerfile:1.7
FROM node:24-alpine AS ui
WORKDIR /src/ui
ARG NPM_REGISTRY=https://registry.npmjs.org/
COPY ui/package.json ui/package-lock.json ui/.npmrc ./
RUN --mount=type=cache,target=/root/.npm --mount=type=secret,id=build_ca,required=false \
    if [ -f /run/secrets/build_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_ca; fi; \
    npm ci --registry="$NPM_REGISTRY" --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM golang:1.26-bookworm AS server
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=secret,id=goproxy,required=false --mount=type=secret,id=build_ca,required=false \
    if [ -f /run/secrets/goproxy ]; then export GOPROXY="$(cat /run/secrets/goproxy)"; fi; \
    if [ -f /run/secrets/build_ca ]; then export SSL_CERT_FILE=/run/secrets/build_ca; fi; \
    go mod download
COPY . .
COPY --from=ui /src/ui/dist/ ./internal/web/dist/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/barktrace ./cmd/barktrace && \
    mkdir -p /out/data && chown 65532:65532 /out/data

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="Barktrace" \
      org.opencontainers.image.description="Lean, self-hosted observability with Sentry SDK compatibility" \
      org.opencontainers.image.source="https://github.com/barktrace/bark"
WORKDIR /app
COPY --from=server /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=server /out/barktrace /app/barktrace
COPY --chown=65532:65532 --from=server /out/data /data
VOLUME ["/data"]
EXPOSE 8080
ENV BARKTRACE_ADDR=:8080 BARKTRACE_DATA_DIR=/data GOMEMLIMIT=96MiB
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/barktrace", "healthcheck"]
ENTRYPOINT ["/app/barktrace"]
