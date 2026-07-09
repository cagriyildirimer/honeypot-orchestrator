# Build stage
FROM golang:1.25-alpine AS builder

# Install iptables, headers and build essentials
RUN apk add --no-cache git build-base libpcap-dev libnetfilter_queue-dev

WORKDIR /app

# Copy dependency manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build daemon executable
RUN CGO_ENABLED=1 GOOS=linux go build -o /app/honeypot-daemon cmd/honeypot-daemon/main.go

# Final runtime stage
FROM alpine:3.19

# Install iptables, packet capture and netfilter-queue dependencies
RUN apk add --no-cache iptables libpcap libnetfilter_queue

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/honeypot-daemon /app/honeypot-daemon

# Create config/logs placeholders
RUN mkdir -p /app/logs

# Expose ports
EXPOSE 8000 80 8080 21 22 23 53 135 139 389 445 636 1433 3389 1445 2222 2223 2121 2323 5355/udp 137/udp 1053/udp

# Run daemon
CMD ["/app/honeypot-daemon", "--config", "config.yaml"]
