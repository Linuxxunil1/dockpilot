FROM python:3.12-slim

ARG DOCKER_VERSION=27.1.1
ARG COMPOSE_VERSION=v2.29.2
ARG TARGETARCH

# Docker static CLI + Compose plugin (no daemon needed)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && ARCH=$(uname -m) \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${ARCH}/docker-${DOCKER_VERSION}.tgz" \
       | tar xz --strip-components=1 -C /usr/local/bin docker/docker \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${ARCH}" \
       -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
