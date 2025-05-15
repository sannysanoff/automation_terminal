FROM python:3.11-slim-bookworm

# Install dependencies for Go and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential git procps \
    && rm -rf /var/lib/apt/lists/*

# Set Go version
ENV GOVERSION=1.24.3

# Download and install Go based on architecture
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

# Copy source code
WORKDIR /src
COPY . .

# Build Go project
RUN go build -o /automation_terminal

# Default command
CMD ["/automation_terminal"]
