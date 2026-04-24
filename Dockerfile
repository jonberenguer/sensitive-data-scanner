# Multi-stage build: compile Go binary then produce a minimal runtime image.
# Build the image:  docker build -t sensitive-data-scanner .
# Run a demo scan:  docker run --rm sensitive-data-scanner
# Scan a host dir:  docker run --rm -v /host/path:/target -v /host/out:/out \
#                     sensitive-data-scanner /target --out /out

FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY src/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /scanner .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /scanner /usr/local/bin/scanner
COPY patterns.json .
COPY fixtures/ ./fixtures/

# Default: scan the bundled fixtures so the image is self-demonstrating.
ENTRYPOINT ["scanner"]
CMD ["/app/fixtures", "--patterns", "/app/patterns.json", "--out", "/tmp/scan-results"]
