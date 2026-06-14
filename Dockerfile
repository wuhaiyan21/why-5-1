FROM golang:1.21-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git

COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /out/logalyzer \
    ./cmd/logalyzer

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /out/logalyzer /usr/local/bin/logalyzer
COPY config.yaml /app/config.yaml

RUN chmod +x /usr/local/bin/logalyzer

ENV LOG_DIR=/var/log

ENTRYPOINT ["logalyzer"]
CMD ["--config", "/app/config.yaml"]
