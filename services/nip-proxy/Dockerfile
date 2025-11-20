FROM golang:1.25.4-alpine AS builder

WORKDIR /build

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY pkg ./pkg
COPY services/nip-proxy ./services/nip-proxy

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o main ./services/nip-proxy

FROM debian:stable-slim AS runner

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates

COPY --from=builder /build/main /app/main

ENTRYPOINT ["/app/main"]