FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -o main ./cmd/main.go

# Generate self-signed certificates for development
RUN apk add --no-cache openssl && \
    mkdir -p /app/certs && \
    openssl req -x509 -newkey rsa:4096 -keyout /app/certs/key.pem -out /app/certs/cert.pem -days 365 -nodes -subj "/CN=localhost"

# Use a smaller image for the final container
FROM alpine:latest

WORKDIR /app

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy the binary and certificates from the builder
COPY --from=builder /app/main .
COPY --from=builder /app/certs ./certs
COPY --from=builder /app/server/controllers/templates ./server/controllers/templates

# Create directory for database and redis if needed
RUN mkdir -p /data

# Expose the application port
EXPOSE 8050

# Environment variables will be provided during deployment
ENV DEW_AUTH_SERVER_HOST="0.0.0.0" \
    DEW_AUTH_SERVER_PORT="8050" \
    DEW_AUTH_SERVER_TLS_CERT_PATH="./certs/cert.pem" \
    DEW_AUTH_SERVER_TLS_KEY_PATH="./certs/key.pem" \
    DEW_AUTH_SERVER_TEMPLATE_PATH="./server/controllers/templates" \
    DEW_AUTH_LOGGING_LEVEL="info"

# Run the application
CMD ["./main"]