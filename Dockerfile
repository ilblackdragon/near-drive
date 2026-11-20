# NEAR Drive server image: the gateway and the S3-compatible endpoint.
#
#   docker build -t near-drive .
#   docker run -p 127.0.0.1:8787:8787 -e NEAR_DRIVE_CONFIG_JSON='{"listen":"0.0.0.0:8787","data_dir":"/data",...}' near-drive
#   docker run -p 127.0.0.1:9000:9000 -e ... near-drive near-drive --no-interactive --account app.near s3-proxy --listen 0.0.0.0:9000 --public-listen
#
# See docs/deploy.md. Inside the container the listeners bind 0.0.0.0 (the
# container's own interface); publish ports on 127.0.0.1 or a private address.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin near-drive-gateway --bin near-drive \
    && mkdir -p /out && cp target/release/near-drive-gateway target/release/near-drive /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /data --uid 10001 drive
COPY --from=build /out/near-drive-gateway /out/near-drive /usr/local/bin/
USER drive
WORKDIR /data
ENV HOME=/data NEAR_DRIVE_HOME=/data/near-drive RUST_LOG=info
VOLUME ["/data"]
EXPOSE 8787 9000
# Gateway by default; config from NEAR_DRIVE_CONFIG_JSON or --config.
CMD ["near-drive-gateway"]
