# Stage 1: Build Vue 3 SPA Frontend
FROM node:22-alpine AS web-builder
WORKDIR /build/web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Stage 2: Build Rust Panel Single Binary (with embedded SPA)
FROM rust:1-bookworm AS rust-builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* build.rs ./
COPY src/ ./src/
COPY --from=web-builder /build/web/dist ./web/dist
RUN cargo build --release

# Stage 3: Runtime Image with cfal/shoes + shoes-panel
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tar tzdata \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) SHOES_TARGET="x86_64-unknown-linux-musl" ;; \
      arm64) SHOES_TARGET="aarch64-unknown-linux-musl" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    mkdir -p /tmp/shoes-dl /usr/share/doc/shoes; \
    if curl -fsSL "https://github.com/cfal/shoes/releases/latest/download/shoes-${SHOES_TARGET}.tar.gz" -o /tmp/shoes-dl/shoes.tar.gz; then \
      tar -xzf /tmp/shoes-dl/shoes.tar.gz -C /tmp/shoes-dl; \
      install -m 0755 "$(find /tmp/shoes-dl -type f -name shoes | head -n 1)" /usr/local/bin/shoes; \
      find /tmp/shoes-dl -maxdepth 2 \( -name "LICENSE*" -o -name "THIRD_PARTY*" -o -name "licenses" \) -exec cp -r {} /usr/share/doc/shoes/ \; || true; \
    fi; \
    rm -rf /tmp/shoes-dl

COPY --from=rust-builder /build/target/release/shoes-panel /usr/local/bin/shoes-panel

VOLUME ["/etc/shoes-panel"]
ENV SHOES_PANEL_DATA=/etc/shoes-panel
ENV PANEL_PORT=54321
ENV RUST_LOG=shoes_panel=info

EXPOSE 54321

ENTRYPOINT ["/usr/local/bin/shoes-panel"]
CMD ["serve", "--data-dir", "/etc/shoes-panel"]
