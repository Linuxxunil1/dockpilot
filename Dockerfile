# ── Build stage ─────────────────────────────────────────────────────────────
# Basis-Images per Digest gepinnt (Tag zur Lesbarkeit); Updates z. B. über Dependabot/Renovate.
FROM golang:1.26-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /dockpilot ./cmd/dockpilot/

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63

RUN apk add --no-cache \
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
