FROM golang:1.24-alpine AS builder

# Install build tools like git and ca-certificates
RUN apk add --no-cache git

WORKDIR /app

# Copy module files and download dependencies
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy source code
COPY . ./

RUN go build -o server .

# Run stage
FROM debian:bookworm-slim
WORKDIR /app

COPY --from=builder /app/server .

ENTRYPOINT ["./server"]