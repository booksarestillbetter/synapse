# Stage 1: Build — full Rust toolchain, workspace compiled from source.
# io_uring is a runtime concern (needs a 5.1+ host kernel; synapse-diskio falls back to
# POSIX I/O automatically when it isn't available), not a build-time one, so no special
# kernel/headers requirement here beyond a normal Rust build environment.
FROM rust:1.94-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config protobuf-compiler libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release -p synapsed

# Stage 2: Runtime — minimal Debian base, just the one binary and CA certs (tracker
# announces over HTTPS need them).
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gosu && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/synapsed /usr/local/bin/synapsed

# Default config template
COPY example_config.toml /etc/synapse/synapse.toml.default

RUN useradd --system --create-home --home-dir /var/lib/synapse synapse \
    && mkdir -p /data/downloads /var/lib/synapse/session /etc/synapse /media \
    && chown -R synapse:synapse /data /var/lib/synapse /etc/synapse /media

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME ["/data", "/var/lib/synapse"]

# gRPC control plane, REST/Swagger/metrics, BitTorrent peer port (TCP+UDP).
EXPOSE 50051 8080 54345 54345/udp

# Healthcheck probes HTTP health if enabled, or falls back to verifying synapsed is running.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/v1/health 2>/dev/null || pidof synapsed >/dev/null || exit 1

WORKDIR /var/lib/synapse
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
