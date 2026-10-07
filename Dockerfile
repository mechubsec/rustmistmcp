# The builder digest is an OCI index supporting the release architectures.
FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS builder
WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY docs/mist-api/catalog.json ./docs/mist-api/catalog.json
RUN cargo build --release --locked --bin rustmistmcp

# This distroless Debian 13 image supplies the required CA trust store.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97
ARG VERSION=0.0.0-pre-release
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="rustmistmcp" \
      org.opencontainers.image.description="Pre-release MCP server for HPE Juniper Mist" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$CREATED" \
      org.opencontainers.image.source="https://github.com/mechubsec/rustmistmcp" \
      org.opencontainers.image.licenses="MIT"
# Official MCP Registry ownership check: must equal server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/rustmistmcp"
COPY --from=builder /workspace/target/release/rustmistmcp /usr/local/bin/rustmistmcp
USER 65532:65532
EXPOSE 30030
STOPSIGNAL SIGTERM
# --audit-hmac-key-file: this image is distroless with no shell, so a
# shell-script key-generation wrapper (as LXC's install.sh uses) can never
# run here. Instead the binary itself generates the key file on first run if
# it is absent (see ensure_audit_hmac_key in src/main.rs) -- the
# container-image equivalent of install.sh's own key-generation step,
# closing the "5 of 6 server images run unkeyed audit" gap (mecmcp#376 /
# MEC-978). The path is under the writable /var/lib/rustmistmcp volume, not
# /etc/rustmistmcp, which a documented `docker run` may mount read-only.
ENTRYPOINT [ \
    "/usr/local/bin/rustmistmcp", \
    "--device-mapping", "/etc/rustmistmcp/mist.json", \
    "--tokens-file", "/var/lib/rustmistmcp/tokens.json", \
    "--audit-format", "json", \
    "--audit-redact", "devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac", \
    "--audit-hmac-key-file", "/var/lib/rustmistmcp/audit-hmac.key" \
]
CMD ["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "30030"]
