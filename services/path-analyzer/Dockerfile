FROM golang:1.25.4-alpine AS builder

WORKDIR /build

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY pkg ./pkg
COPY services/path-analyzer ./services/path-analyzer

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o main ./services/path-analyzer

FROM scratch AS runner

WORKDIR /app

COPY --from=builder /build/main /app/main

ENTRYPOINT ["/app/main"]