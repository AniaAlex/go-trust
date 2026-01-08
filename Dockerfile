# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies (git for deps, gcc/musl for CGO/PKCS#11)
RUN apk add --no-cache git ca-certificates gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with version information
# CGO required for PKCS#11 support via crypto11
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -linkmode external -extldflags '-static' -X github.com/sirosfoundation/go-trust/pkg/version.Version=${VERSION} -X github.com/sirosfoundation/go-trust/pkg/version.Commit=${COMMIT} -X github.com/sirosfoundation/go-trust/pkg/version.Date=${BUILD_DATE}" \
    -o gt ./cmd/gt

# Runtime stage - using distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/gt /app/gt

# Copy example configuration (optional, can be overridden at runtime)
COPY --from=builder /app/example /app/example

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/gt"]
CMD ["serve"]
