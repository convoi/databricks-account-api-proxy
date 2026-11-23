# Build stage
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=0.1.1

WORKDIR /build

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates tzdata

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build statically compiled binaries for target platform
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /build/proxy ./cmd/proxy

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /build/terraform-provider-databricks-proxy ./cmd/terraform-provider-databricks-proxy

# Production runtime stage
FROM alpine:3.20

# Create non-root user
RUN addgroup -S appgroup && adduser -S -u 10001 -G appgroup appuser

# Install CA certificates for TLS upstream communication
RUN apk add --no-cache ca-certificates tzdata curl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/proxy /app/proxy
COPY --from=builder /build/terraform-provider-databricks-proxy /app/terraform-provider-databricks-proxy

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/proxy"]
