# syntax=docker/dockerfile:1.6
#
# MPRD root image (mprd-cli).
# - Default: fast dev build with placeholder Risc0 methods (RISC0_SKIP_BUILD=1).
# - Optional: production build embeds real Risc0 methods (RISC0_BUILD=1).
#
# NOTE: Embedding Risc0 methods requires additional toolchain install steps; see `methods/README.md`.

ARG RUST_VERSION=1.87.0

FROM rust:${RUST_VERSION}-slim-bookworm AS builder

ARG RISC0_BUILD=0

ENV CARGO_TERM_COLOR=always
ENV CARGO_INCREMENTAL=0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    build-essential \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy source (kept simple; adjust to your preferred build-cache strategy).
COPY . .

# Optional: install Risc0 toolchain + enable fail-closed method embedding.
RUN if [ "${RISC0_BUILD}" = "1" ]; then \
      cargo install cargo-risczero --locked && \
      cargo risczero install && \
      rustup target add riscv32im-risc0-zkvm-elf --toolchain risc0 ; \
    fi

# Build mprd CLI.
RUN if [ "${RISC0_BUILD}" = "1" ]; then \
      RISC0_FORCE_BUILD=1 cargo build -p mprd-cli --release ; \
    else \
      RISC0_SKIP_BUILD=1 cargo build -p mprd-cli --release ; \
    fi

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin mprd \
 && mkdir -p /data \
 && chown -R mprd:mprd /data

COPY --from=builder /src/target/release/mprd /usr/local/bin/mprd

USER mprd
WORKDIR /data
VOLUME ["/data"]

EXPOSE 8080
ENTRYPOINT ["mprd"]
