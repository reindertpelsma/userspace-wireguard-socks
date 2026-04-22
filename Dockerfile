FROM golang:1.25-alpine AS builder
RUN apk add --no-cache ca-certificates git
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG BUILD_TAGS=""
RUN if [ -n "$BUILD_TAGS" ]; then \
      CGO_ENABLED=0 go build -trimpath -tags "$BUILD_TAGS" -ldflags='-s -w' -o /out/uwgsocks ./cmd/uwgsocks; \
    else \
      CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/uwgsocks ./cmd/uwgsocks; \
    fi

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=builder /out/uwgsocks /app/uwgsocks
COPY docker/uwgsocks-entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

VOLUME ["/config"]
EXPOSE 51820/udp 1080 8118

ENV UWG_CONFIG_FILE=/config/uwgsocks.yaml

ENTRYPOINT ["/entrypoint.sh"]
