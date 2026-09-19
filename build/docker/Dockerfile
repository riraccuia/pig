# syntax=docker/dockerfile:1

# Build context must be the repository root:
#   docker build -f build/docker/Dockerfile .

FROM golang:1.27 AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /out/pig ./cmd/pig

FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates nftables

COPY build/docker/start.sh /start.sh
RUN chmod +x /start.sh

COPY --from=builder /out/pig /pig

ENTRYPOINT ["/start.sh"]
