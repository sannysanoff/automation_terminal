# --- Build stage ---
FROM python:3.11-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential git procps \
    && rm -rf /var/lib/apt/lists/*

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

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /src
COPY . .

RUN go build -o /automation_terminal

# --- Final image ---
FROM python:3.11-slim-bookworm

WORKDIR /
COPY --from=build /automation_terminal /automation_terminal

CMD ["/automation_terminal"]
