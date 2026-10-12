#!/usr/bin/env bash
# Static delivery-policy contract for pre-release rustmistmcp artifacts.
# Dollar expressions in single quotes below are intentionally matched as
# literal source/workflow text rather than expanded by this policy script.
# shellcheck disable=SC2016
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

failures=0

require_file() {
    if [[ ! -f $1 ]]; then
        printf 'missing required file: %s\n' "$1" >&2
        failures=$((failures + 1))
    fi
}

require_contains() {
    local file=$1
    local pattern=$2
    if ! grep -Fq -- "$pattern" "$file"; then
        printf 'missing required text in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_regex() {
    local file=$1
    local pattern=$2
    if ! grep -Eq -- "$pattern" "$file"; then
        printf 'missing required pattern in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_absent() {
    local file=$1
    local pattern=$2
    if grep -Eq -- "$pattern" "$file"; then
        printf 'forbidden text in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_count() {
    local file=$1
    local pattern=$2
    local expected=$3
    local actual
    actual=$(grep -Fc -- "$pattern" "$file" || true)
    if [[ $actual -ne $expected ]]; then
        printf 'unexpected count in %s for %s: expected %s, got %s\n' \
            "$file" "$pattern" "$expected" "$actual" >&2
        failures=$((failures + 1))
    fi
}

require_before() {
    local file=$1
    local first=$2
    local second=$3
    local first_line
    local second_line
    first_line=$(grep -nF -- "$first" "$file" | head -n 1 | cut -d: -f1 || true)
    second_line=$(grep -nF -- "$second" "$file" | head -n 1 | cut -d: -f1 || true)
    if [[ -z $first_line || -z $second_line || $first_line -ge $second_line ]]; then
        printf 'required ordering missing in %s: %s before %s\n' "$file" "$first" "$second" >&2
        failures=$((failures + 1))
    fi
}

required_files=(
    .dockerignore
    .gitleaksignore
    Dockerfile
    .github/dependabot.yml
    packaging/container/compose.example.yaml
    packaging/lxc/install.sh
    packaging/systemd/rustmistmcp.service
    packaging/systemd/rustmistmcp.sysusers
    packaging/systemd/rustmistmcp.tmpfiles
    scripts/build-release.sh
    scripts/smoke-oci.sh
    scripts/smoke-release-archive.sh
    scripts/test-lxc-installer.sh
    .github/workflows/ci.yml
    .github/workflows/release.yml
    .github/workflows/security.yml
)
for file in "${required_files[@]}"; do
    require_file "$file"
done

# The Rust toolchain version appears in five places that must agree: the
# Dockerfile builder stage, the release workflow's archive builder, two calls in
# smoke-oci.sh, and rust-toolchain.toml. Dependabot bumps only the Dockerfile,
# which would leave the container built with one toolchain and the archive with
# another — a difference that shows up as a glibc or codegen mismatch at install
# time, not at build time. This makes a partial bump fail here instead.
rust_image_refs=$(grep -rhoE 'rust:[0-9]+\.[0-9]+\.[0-9]+-slim-bookworm@sha256:[0-9a-f]{64}' \
    Dockerfile .github/workflows/release.yml scripts/smoke-oci.sh | sort -u)
if [[ $(printf '%s\n' "$rust_image_refs" | grep -c .) -ne 1 ]]; then
    printf 'rust builder image is not consistent across Dockerfile, release.yml and smoke-oci.sh:\n%s\n' \
        "$rust_image_refs" >&2
    failures=$((failures + 1))
fi
rust_image_version=$(printf '%s' "$rust_image_refs" | sed -E 's|^rust:([0-9]+\.[0-9]+\.[0-9]+).*|\1|')
rust_channel=$(grep -oE '^channel[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"' rust-toolchain.toml \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
if [[ -n $rust_image_version && $rust_image_version != "$rust_channel" ]]; then
    printf 'rust-toolchain.toml channel (%s) does not match the builder image (%s)\n' \
        "$rust_channel" "$rust_image_version" >&2
    failures=$((failures + 1))
fi

if (( failures > 0 )); then
    printf 'packaging policy: FAIL (%d violation(s))\n' "$failures" >&2
    exit 1
fi

dockerfile=Dockerfile
compose=packaging/container/compose.example.yaml
installer=packaging/lxc/install.sh
unit=packaging/systemd/rustmistmcp.service
sysusers=packaging/systemd/rustmistmcp.sysusers
tmpfiles=packaging/systemd/rustmistmcp.tmpfiles

# Digest-pinned, not frozen at one version — see the note on the workflow action
# pins below. A Rust bump must still move all five references together
# (Dockerfile, release.yml, smoke-oci.sh x2, rust-toolchain.toml), which the
# consistency check right after this enforces.
require_regex "$dockerfile" '^FROM rust:[0-9]+\.[0-9]+\.[0-9]+-slim-bookworm@sha256:[0-9a-f]{64} AS builder$'
require_regex "$dockerfile" '^FROM gcr\.io/distroless/cc-debian13:nonroot@sha256:[0-9a-f]{64}$'
require_absent "$dockerfile" '^# syntax='
require_contains "$dockerfile" 'USER 65532:65532'
require_contains "$dockerfile" 'EXPOSE 30030'
require_contains "$dockerfile" 'COPY docs/mist-api/catalog.json ./docs/mist-api/catalog.json'

# ENTRYPOINT must contain security-relevant flags and config paths (#78).
# The ENTRYPOINT is multi-line so check each flag appears in the file (they are
# all within the ENTRYPOINT block per the visual inspection above).
require_contains "$dockerfile" '"--audit-format", "json",'
require_contains "$dockerfile" '"--audit-redact", "devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac",'
require_contains "$dockerfile" '"--audit-hmac-key-file", "/var/lib/rustmistmcp/audit-hmac.key"'
require_contains "$dockerfile" '"--tokens-file", "/var/lib/rustmistmcp/tokens.json",'
require_contains "$dockerfile" '"--device-mapping", "/etc/rustmistmcp/mist.json",'

# CMD must be single-line and contain transport, host, port.
require_contains "$dockerfile" 'CMD ["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "30030"]'

# Regression guard for #78: CMD must NOT contain audit flags or config paths.
require_absent "$dockerfile" 'CMD.*--audit-format'
require_absent "$dockerfile" 'CMD.*--audit-redact'
require_absent "$dockerfile" 'CMD.*--audit-hmac-key-file'
require_absent "$dockerfile" 'CMD.*--tokens-file'
require_absent "$dockerfile" 'CMD.*--device-mapping'

# Official MCP Registry ownership label must equal server.json "name".
# The OCI identifier tracks the workspace package version so the next release
# tag and the manifest stay the same string. The package is GHCR only.
require_contains "$dockerfile" 'LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/rustmistmcp"'
if ! python3 - << 'PY'
import json, pathlib, re, sys
root = pathlib.Path(".")
server = json.loads((root / "server.json").read_text())
cargo = (root / "Cargo.toml").read_text()
version = re.search(r'(?m)^version = "([^"]+)"', cargo).group(1)
name = "io.github.mechubsec/rustmistmcp"
errors = []
if server.get("name") != name:
    errors.append(f"name {server.get('name')!r} != {name}")
if server.get("version") != version:
    errors.append(f"version {server.get('version')!r} != Cargo.toml {version}")
desc = server.get("description") or ""
if not 1 <= len(desc) <= 100:
    errors.append(f"description length {len(desc)} outside 1..100")
pkgs = server.get("packages") or []
if len(pkgs) != 1:
    errors.append(f"expected one package, found {len(pkgs)}")
else:
    pkg = pkgs[0]
    expect = f"ghcr.io/mechubsec/rustmistmcp:{version}"
    if pkg.get("identifier") != expect:
        errors.append(f"identifier {pkg.get('identifier')!r} != {expect}")
    if pkg.get("registryType") != "oci":
        errors.append("registryType is not oci")
    if (pkg.get("transport") or {}).get("type") != "stdio":
        errors.append("transport is not stdio")
    banned = {
        "--device-mapping",
        "--tokens-file",
        "--audit-format",
        "--audit-redact",
        "--audit-hmac-key-file",
    }
    args = pkg.get("packageArguments") or []
    names = {arg.get("name") for arg in args}
    if "--transport" not in names or "--state-file" not in names:
        errors.append("package arguments must set --transport and --state-file")
    for arg in args:
        if arg.get("name") in banned:
            errors.append(f"package argument repeats entrypoint flag {arg.get('name')}")
        if arg.get("name") == "--state-file" and arg.get("value") != "/var/lib/rustmistmcp/changeset-state.json":
            errors.append("state file is not the default change-set path")
if errors:
    print("server.json: " + "; ".join(errors), file=sys.stderr)
    sys.exit(1)
PY
then
    printf '%s\n' 'server.json does not match the registry contract' >&2
    failures=$((failures + 1))
fi

require_absent "$dockerfile" --audit-journald
require_contains "$dockerfile" 'STOPSIGNAL SIGTERM'
require_absent "$dockerfile" '(apt-get|apk add|dnf install|yum install|curl |wget |/bin/sh)'
for ignored in '.git' '.worktrees' 'target' 'dist' 'tokens.json' '*.tokens.json' '.env' '*.pem' '*.key' '!docs/mist-api/catalog.json'; do
    require_contains .dockerignore "$ignored"
done

require_contains "$compose" 'user: "65532:65532"'
require_contains "$compose" 'network_mode: host'
require_contains "$compose" 'read_only: true'
require_contains "$compose" 'cap_drop:'
require_contains "$compose" '- ALL'
require_contains "$compose" 'no-new-privileges:true'
require_contains "$compose" 'pids_limit:'
require_contains "$compose" '/etc/rustmistmcp:ro'
require_contains "$compose" '/var/lib/rustmistmcp:rw'
require_absent "$compose" '/run/systemd/journal/socket'
require_contains "$compose" 'size=16m'
require_absent "$compose" '(MIST.*TOKEN|TOKEN=.*|API_KEY|APIKEY|SECRET=.*)'
require_absent "$compose" '(ports:|--host 0\.0\.0\.0|--allow-insecure-bind)'

require_contains "$sysusers" 'u rustmistmcp - "rustmistmcp service user" /var/lib/rustmistmcp'
require_contains "$tmpfiles" 'd /etc/rustmistmcp 0750 root rustmistmcp -'
require_contains "$tmpfiles" 'd /var/lib/rustmistmcp 0700 rustmistmcp rustmistmcp -'

require_contains "$unit" 'User=rustmistmcp'
require_contains "$unit" 'Group=rustmistmcp'
require_contains "$unit" 'UMask=0077'
require_contains "$unit" 'ReadOnlyPaths=/etc/rustmistmcp'
require_contains "$unit" 'ReadWritePaths=/var/lib/rustmistmcp'
require_contains "$unit" 'NoNewPrivileges=true'
require_contains "$unit" 'CapabilityBoundingSet='
require_contains "$unit" 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
require_contains "$unit" 'TasksMax='
require_contains "$unit" 'LimitNOFILE='
for runtime_arg in \
    'ExecStart=/usr/local/bin/rustmistmcp' \
    '--device-mapping /etc/rustmistmcp/mist.json' \
    '--transport streamable-http' \
    '--host 127.0.0.1' \
    '--port 30030' \
    '--tokens-file /var/lib/rustmistmcp/tokens.json' \
    '--audit-format json' \
    '--audit-journald' \
    '--audit-redact devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac' \
    '--audit-hmac-key-file /etc/rustmistmcp/audit-hmac.key'; do
    require_contains "$unit" "$runtime_arg"
done
require_absent "$unit" '(changeset-state|mutation-state|--state)'

require_contains "$installer" 'umask 077'
require_contains "$installer" 'work=$(mktemp -d)'
require_contains "$installer" 'chmod 0700 "$work"'
require_contains "$installer" 'cp --no-dereference --archive --no-target-directory -- "$archive_arg" "$archive"'
require_contains "$installer" 'cp --no-dereference --archive --no-target-directory -- "$checksum_arg" "$checksum"'
require_contains "$installer" '[[ -f $archive && ! -L $archive && -r $archive ]]'
require_contains "$installer" '[[ -f $checksum && ! -L $checksum && -r $checksum ]]'
require_contains "$installer" 'tar --absolute-names -tzf "$archive"'
require_contains "$installer" 'tar --absolute-names -tvzf "$archive"'
require_absent "$installer" 'tar[[:space:]]+--absolute-names[[:space:]]+-x'
require_contains "$installer" 'require_safe_live_secret /var/lib/rustmistmcp/tokens.json'
require_contains "$installer" 'require_safe_live_secret /etc/rustmistmcp/audit-hmac.key'
require_contains "$installer" 'require_safe_live_secret /etc/rustmistmcp/mist-api-token'
require_contains "$installer" '[[ ! -L $path ]]'
require_contains "$installer" '[[ ! -e $path || -f $path ]]'
require_before "$installer" 'require_safe_live_secret /var/lib/rustmistmcp/tokens.json' 'apt-get update'
require_before "$installer" 'require_safe_live_secret /etc/rustmistmcp/audit-hmac.key' 'apt-get update'
require_before "$installer" 'require_safe_live_secret /etc/rustmistmcp/mist-api-token' 'apt-get update'
require_contains "$installer" 'apt-get update -qq'
require_contains "$installer" 'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates'
require_contains "$installer" 'apt-get clean'
require_contains "$installer" 'rm -rf /var/lib/apt/lists/*'
require_contains "$installer" '--validate-only'
require_contains "$installer" 'systemd-detect-virt'
require_contains "$installer" 'VERSION_ID'
require_contains "$installer" 'RUSTMISTMCP_LXC_HOST_PROOF'
require_contains "$installer" 'find -P'
require_contains "$installer" 'realpath'
require_contains "$installer" '/var/lib/rustmistmcp/tokens.json'
require_contains "$installer" '/etc/rustmistmcp/audit-hmac.key'
require_contains "$installer" 'install -m 0600'
require_contains "$installer" 'systemctl daemon-reload'
require_absent "$installer" 'systemctl enable'

require_contains scripts/build-release.sh 'git status --porcelain=v1 --untracked-files=all'
require_contains scripts/build-release.sh 'umask 022'
require_contains scripts/build-release.sh 'CARGO_TARGET_DIR'
require_contains scripts/build-release.sh 'RUSTMISTMCP_CI_SOURCE_VERIFIED'
require_contains scripts/build-release.sh 'RUSTMISTMCP_COMMIT'
require_contains scripts/build-release.sh 'RUSTMISTMCP_RELEASE_VERSION'
require_contains scripts/build-release.sh 'SOURCE_DATE_EPOCH'
require_contains scripts/build-release.sh 'gzip -n'
require_contains scripts/build-release.sh 'BUILD-INFO'
require_contains scripts/build-release.sh 'docs/OPERATIONS.md'
require_contains scripts/build-release.sh 'docs/PACKAGING_ACCEPTANCE.md'
require_contains scripts/smoke-release-archive.sh 'cp --no-dereference --archive --no-target-directory -- "$archive_arg" "$archive"'
require_contains scripts/smoke-release-archive.sh 'cp --no-dereference --archive --no-target-directory -- "$sidecar_arg" "$sidecar"'
require_contains scripts/smoke-release-archive.sh '[[ -f $archive && ! -L $archive && -r $archive ]]'
require_contains scripts/smoke-release-archive.sh '[[ -f $sidecar && ! -L $sidecar && -r $sidecar ]]'
require_absent scripts/smoke-release-archive.sh 'tar[[:space:]]+--absolute-names[[:space:]]+-x'

# Uses grep, not ripgrep. `rg` is not installed on the GitHub runner, and both
# call sites failed *open*: the loop below simply read nothing, so the check that
# every workflow action is pinned to a 40-hex SHA silently passed on every CI run
# it has ever made. The Command::new check below had the same shape — a missing
# binary makes the `if` false, so no violation is reported.
while IFS= read -r action_line; do
    if [[ ! $action_line =~ uses:[[:space:]]+[^[:space:]@]+@[0-9a-f]{40}[[:space:]]*$ ]]; then
        printf 'workflow action is not pinned to exactly 40 hex: %s\n' "$action_line" >&2
        failures=$((failures + 1))
    fi
done < <(grep -rE '^[[:space:]]*-[[:space:]]+uses:' .github/workflows --include='*.yml' --include='*.yaml' | cut -d: -f2-)
# These assert that each action and the builder image are *pinned*, not that they
# sit at one frozen revision. The security property is "resolved by immutable
# digest, never by a mutable tag", and the 40-hex sweep above enforces it across
# every workflow. Freezing the exact SHA additionally made every dependabot bump
# fail policy, which is a change-detector rather than a control — and one that
# encourages merging around the gate.
require_regex .github/workflows/ci.yml 'actions/checkout@[0-9a-f]{40}'
require_regex .github/workflows/release.yml 'actions/checkout@[0-9a-f]{40}'
require_regex .github/workflows/security.yml 'actions/checkout@[0-9a-f]{40}'
for workflow in .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/security.yml; do
    if ! awk '
        function finish_checkout() {
            if (in_checkout && !credentials_disabled) {
                exit 1
            }
            in_checkout = 0
            credentials_disabled = 0
        }
        /^[[:space:]]*-[[:space:]]+uses:[[:space:]]+actions\/checkout@/ {
            finish_checkout()
            in_checkout = 1
            checkout_indent = match($0, /[^[:space:]]/) - 1
            next
        }
        in_checkout {
            current_indent = match($0, /[^[:space:]]/) - 1
            if ($0 ~ /^[[:space:]]*-[[:space:]]+/ && current_indent == checkout_indent) {
                finish_checkout()
                next
            }
            if ($0 ~ /^[[:space:]]+persist-credentials:[[:space:]]+false[[:space:]]*$/) {
                credentials_disabled = 1
            }
        }
        END {
            finish_checkout()
        }
    ' "$workflow"; then
        printf 'every checkout must set persist-credentials:false: %s\n' "$workflow" >&2
        failures=$((failures + 1))
    fi
done
require_contains .github/workflows/release.yml 'platforms: linux/amd64'
require_contains .github/workflows/release.yml 'provenance: mode=max'
require_contains .github/workflows/release.yml 'sbom: true'
require_contains .github/workflows/release.yml "tags: ['v*-rc*', 'v*.*.*']"
require_contains .github/workflows/release.yml 'needs: verify'
require_contains .github/workflows/release.yml 'Validate release tag against Cargo version'
require_regex .github/workflows/release.yml 'rust:[0-9]+\.[0-9]+\.[0-9]+-slim-bookworm@sha256:[0-9a-f]{64}'
# These were `require_absent` while the shared CLI had no `--version`
# (mecmcp#159) and a workflow mentioning it would have been claiming an
# identity check that exits 2. The flag is wired now, so the container smoke
# must actually exercise it.
require_contains .github/workflows/ci.yml '--version'
require_contains .github/workflows/ci.yml '--help'
require_contains .github/workflows/ci.yml 'rustup toolchain install 1.89.0 --profile minimal'
require_contains .github/workflows/ci.yml 'scripts/smoke-oci.sh'
require_contains .github/workflows/ci.yml 'RUSTMISTMCP_BINARY=target/release/rustmistmcp scripts/verify-packaging.sh'
require_contains .github/workflows/release.yml 'RUSTMISTMCP_BINARY=target/release/rustmistmcp scripts/verify-packaging.sh'
# The secret scan is the shared mechubsec workflow, pinned by commit SHA; the
# gitleaks version and checksum are pinned there.
require_contains .github/workflows/security.yml 'uses: mechubsec/.github/.github/workflows/gitleaks.yml@1f46f69afab3cc1c77efa196747bc3a5e45a3755'
require_absent .github/workflows/security.yml 'gitleaks/gitleaks-action|GITLEAKS_LICENSE'
require_contains .github/workflows/security.yml 'pull-requests: read'
gitleaks_ignored_findings=(
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/catalog.json:azure-ad-client-secret:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/catalog.json:generic-api-key:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/catalog.json:jwt:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/catalog.json:private-key:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/mist-openapi.json:azure-ad-client-secret:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/mist-openapi.json:generic-api-key:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/mist-openapi.json:jwt:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/mist-openapi.json:private-key:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/catalog.json:pem-private-key:1'
    '590c24ac8fce739487f3d2aed2c3b23ec1265f8f:docs/mist-api/mist-openapi.json:pem-private-key:1'
    # 2609.1.0 refresh (#127): upstream example values in the byte-identical vendored spec.
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/catalog.json:azure-ad-client-secret:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/catalog.json:generic-api-key:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/catalog.json:jwt:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/catalog.json:private-key:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/catalog.json:pem-private-key:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/mist-openapi.json:azure-ad-client-secret:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/mist-openapi.json:generic-api-key:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/mist-openapi.json:jwt:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/mist-openapi.json:private-key:1'
    'e5fcd8cd5b2f74d507b2160dcca41d2c78b6f5a0:docs/mist-api/mist-openapi.json:pem-private-key:1'
)
if [[ -f .gitleaksignore ]]; then
    for finding in "${gitleaks_ignored_findings[@]}"; do
        require_contains .gitleaksignore "$finding"
    done
    actual_ignored_findings=$(grep -Evc '^[[:space:]]*(#|$)' .gitleaksignore || true)
    if [[ $actual_ignored_findings -ne ${#gitleaks_ignored_findings[@]} ]]; then
        printf 'unexpected Gitleaks ignore count: expected %d, got %d\n' \
            "${#gitleaks_ignored_findings[@]}" "$actual_ignored_findings" >&2
        failures=$((failures + 1))
    fi
fi
require_regex .github/workflows/release.yml 'actions/upload-artifact@[0-9a-f]{40}'
require_regex .github/workflows/release.yml 'actions/attest-build-provenance@[0-9a-f]{40}'
require_regex .github/workflows/release.yml '^permissions: \{\}$'
# 4 = the verify, image and archive jobs + the shared gitleaks caller job, which
# must grant contents: read itself because the workflow top level is permissions: {}.
require_count .github/workflows/release.yml 'contents: read' 4
require_count .github/workflows/release.yml 'packages: write' 1
require_count .github/workflows/release.yml 'id-token: write' 1
require_count .github/workflows/release.yml 'attestations: write' 1
require_contains .github/workflows/release.yml 'cargo +1.89.0 check --workspace --locked'
require_contains .github/workflows/release.yml 'cargo doc --workspace --no-deps --locked'
require_contains .github/workflows/release.yml 'cargo audit'
require_contains .github/workflows/release.yml 'cargo deny check'
require_contains .github/workflows/release.yml 'scripts/verify-reproducible-build.sh'
require_contains .github/workflows/release.yml 'npm exec --yes --package=yaml@2.8.1 yaml -- valid "$file"'
require_contains .github/workflows/release.yml 'uses: mechubsec/.github/.github/workflows/gitleaks.yml@1f46f69afab3cc1c77efa196747bc3a5e45a3755'
require_contains .github/workflows/release.yml 'needs: secrets'
require_absent .github/workflows/release.yml 'gitleaks/gitleaks-action|GITLEAKS_LICENSE'
require_contains .github/dependabot.yml 'package-ecosystem: "github-actions"'
require_contains .github/dependabot.yml 'package-ecosystem: "docker"'
require_contains deny.toml '"MIT-0"'

require_contains README.md 'The Mist vendor API supports API tokens and external OAuth 2.0.'
require_contains README.md 'rustmistmcp v1 intentionally implements API-token authentication only'
require_contains README.md '| **Mist REST client, API-token auth, response models, tool surface** | **this repo** |'
require_absent README.md 'Mist REST client, token/OAuth auth'
require_contains CLAUDE.md 'Mist supports API tokens and external OAuth 2.0, but rustmistmcp v1 intentionally implements API-token authentication only.'
require_absent README.md 'Grant-bearing Mist token'
require_absent README.md 'grant-bearing Mist token'
require_contains README.md 'Grant-bearing MCP bearer-token add/list/revoke/rotate'
# This asserted the lifecycle was blocked by mecmcp#160. That issue closed and
# the local adapter is gone, so the guard now holds the opposite line: the
# lifecycle is the shared command, and CLAUDE.md must not go back to calling it
# blocked.
require_contains CLAUDE.md 'bearer-token lifecycle uses the shared `token_cmd::run_with_grant`'
require_absent CLAUDE.md 'bearer-token lifecycle is blocked by'
require_contains docs/OPERATIONS.md 'sudo install -D -o root -g rustmistmcp -m 0640'
require_contains docs/OPERATIONS.md 'sudo install -o rustmistmcp -g rustmistmcp -m 0600 /dev/null'
require_contains docs/OPERATIONS.md '/etc/rustmistmcp/mist-api-token'
require_contains docs/OPERATIONS.md '/var/lib/rustmistmcp/tokens.json'
require_contains docs/OPERATIONS.md '/etc/rustmistmcp/audit-hmac.key'
require_contains docs/OPERATIONS.md 'shared `mechubsec/.github` gitleaks workflow'
require_contains README.md '`/etc/rustmistmcp/mist.json` | `root:rustmistmcp`, `0640`'
require_contains README.md '`/etc/rustmistmcp/mist-api-token` | `rustmistmcp:rustmistmcp`, `0600`'
require_contains README.md '`/var/lib/rustmistmcp/tokens.json` | `rustmistmcp:rustmistmcp`, `0600`'
require_contains README.md '`/etc/rustmistmcp/audit-hmac.key` | `rustmistmcp:rustmistmcp`, `0600`'

if ! cmp -s examples/mist.example.json packaging/examples/mist.example.json; then
    printf '%s\n' 'packaging Mist example must match checked-in runtime example' >&2
    failures=$((failures + 1))
fi

if ! scripts/test-lxc-installer.sh; then
    printf '%s\n' 'LXC installer behavioral validation failed' >&2
    failures=$((failures + 1))
fi

runtime_binary=${RUSTMISTMCP_BINARY:-target/debug/rustmistmcp}
if [[ ! -x $runtime_binary ]]; then
    printf 'runtime command smoke binary is missing: %s\n' "$runtime_binary" >&2
    failures=$((failures + 1))
elif ! "$runtime_binary" \
    --device-mapping /etc/rustmistmcp/mist.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30030 \
    --tokens-file /var/lib/rustmistmcp/tokens.json \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac \
    --audit-hmac-key-file /etc/rustmistmcp/audit-hmac.key \
    --help >/dev/null; then
    printf '%s\n' 'packaged runtime command does not parse' >&2
    failures=$((failures + 1))
fi

if grep -rn 'Command::new' --include='*.rs' crates/*/src; then
    printf '%s\n' 'runtime process spawning is incompatible with the distroless contract' >&2
    failures=$((failures + 1))
fi

if (( failures > 0 )); then
    printf 'packaging policy: FAIL (%d violation(s))\n' "$failures" >&2
    exit 1
fi
printf 'packaging policy: PASS\n'
