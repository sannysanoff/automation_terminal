# --- Build stage ---
FROM python:3.11-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential git procps mercurial silversearcher-ag \
    tree

ENV GOVERSION=1.24.3

RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64) goarch="amd64" ;; \
        aarch64 | arm64) goarch="arm64" ;; \
        *) echo "Unsupported architecture: $arch" && exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GOVERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tar.gz; \
    rm -rf /usr/local/go; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:/root/.local/bin:${PATH}"

RUN python -m pip install aider-install
RUN aider-install

WORKDIR /src

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o automation_terminal

RUN mkdir /workspace

WORKDIR /workspace


CMD ["/src/automation_terminal","--verbose"]
