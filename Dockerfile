# ── Build stage ─────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /dockpilot ./cmd/dockpilot/

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache \
    bash \
    ca-certificates \
    docker-cli \
    docker-compose

WORKDIR /app
COPY --from=builder /dockpilot .

ENV DATA_DIR=/data \
    STACKS_DIR=/opt/dockpilot/stacks \
    LISTEN_ADDR=:8080

EXPOSE 8080

CMD ["/app/dockpilot"]
