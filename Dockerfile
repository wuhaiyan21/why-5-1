FROM golang:1.21-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git

COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /out/logalyzer \
    ./cmd/logalyzer

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /out/logalyzer-batch \
    ./cmd/logalyzer-batch

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /out/logalyzer /usr/local/bin/logalyzer
COPY --from=builder /out/logalyzer-batch /usr/local/bin/logalyzer-batch
COPY config.yaml /app/config.yaml
COPY batch-config.yaml /app/batch-config.yaml

RUN chmod +x /usr/local/bin/logalyzer /usr/local/bin/logalyzer-batch

ENV LOG_DIR=/var/log
ENV OUTPUT_FORMAT=markdown
ENV OUTPUT_FILE=
ENV ONCE=true

ENV BATCH_CONFIG=/app/batch-config.yaml
ENV BATCH_OUTPUT=/app/batch-results
ENV BATCH_BASE_CONFIG=
ENV VERBOSE=false
ENV NO_HTML=false
ENV MODE=single

ENTRYPOINT ["/bin/sh", "-c", "if [ \"$MODE\" = \"batch\" ]; then ARGS=\"--batch-config ${BATCH_CONFIG} --output ${BATCH_OUTPUT}\"; [ -n \"${BATCH_BASE_CONFIG}\" ] && ARGS=\"${ARGS} --config ${BATCH_BASE_CONFIG}\"; [ \"${VERBOSE}\" = \"true\" ] && ARGS=\"${ARGS} --verbose\"; [ \"${NO_HTML}\" = \"true\" ] && ARGS=\"${ARGS} --no-html\"; exec logalyzer-batch ${ARGS}; else ARGS=\"--config /app/config.yaml --log-dir ${LOG_DIR}\"; [ -n \"${OUTPUT_FORMAT}\" ] && ARGS=\"${ARGS} --format ${OUTPUT_FORMAT}\"; [ -n \"${OUTPUT_FILE}\" ] && ARGS=\"${ARGS} --output ${OUTPUT_FILE}\"; [ \"${ONCE}\" = \"true\" ] && ARGS=\"${ARGS} --once\"; exec logalyzer ${ARGS}; fi"]
