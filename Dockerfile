# Source of libgcc-s1 only; the runtime is base-nossl, which lacks it. Not the
# runtime itself, so keep it ahead of the builder and out of the last FROM.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de AS libgcc

# The builder digest is an OCI index supporting the release architectures.
FROM rust:1.100.0-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS builder
WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY docs/mist-api/catalog.json ./docs/mist-api/catalog.json
RUN cargo build --release --locked --bin rustmistmcp

# libgcc_s.so.1 is the one library the binary needs beyond glibc, and
# base-nossl does not ship it. Stage it with its dpkg records (status.d) so
# Trivy and the SBOM still see libgcc-s1 and gcc-14-base. The multiarch
# directory comes from the builder's own triplet (x86_64 or aarch64).
COPY --from=libgcc / /cc/
RUN triplet="$(gcc -dumpmachine | sed 's/-pc-/-/')" \
    && install -d "/stage-libgcc/usr/lib/${triplet}" /stage-libgcc/var/lib/dpkg/status.d \
    && cp -a "/cc/usr/lib/${triplet}/libgcc_s.so.1" "/stage-libgcc/usr/lib/${triplet}/" \
    && cp -a /cc/var/lib/dpkg/status.d/libgcc-s1 /cc/var/lib/dpkg/status.d/libgcc-s1.md5sums \
        /cc/var/lib/dpkg/status.d/gcc-14-base /cc/var/lib/dpkg/status.d/gcc-14-base.md5sums \
        /stage-libgcc/var/lib/dpkg/status.d/

# Distroless base-nossl supplies the CA trust store without libssl3t64/libcrypto
# (the binary is rustls-only; libssl3t64 carries unfixed CVE-2026-124709).
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:4006ac92504be607b70de01d1f64f38288c69fcd8faa820f6d3aed266ea32ac5
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
COPY --from=builder /stage-libgcc/ /
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
