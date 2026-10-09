#!/usr/bin/env bash
# Start the hardened OCI image with mounted files and prove anonymous rejection.
set -euo pipefail

image=${1:?usage: smoke-oci.sh IMAGE}
command -v docker >/dev/null || { printf '%s\n' 'docker is required' >&2; exit 1; }
command -v curl >/dev/null || { printf '%s\n' 'curl is required' >&2; exit 1; }
[[ $(uname -s) == Linux ]] || { printf '%s\n' 'host-network loopback smoke requires Linux' >&2; exit 1; }

if curl --silent --output /dev/null --max-time 1 http://127.0.0.1:30030/mcp; then
    printf '%s\n' '127.0.0.1:30030 is already serving HTTP' >&2
    exit 1
fi

work=$(mktemp -d)
name="rustmistmcp-oci-smoke-$$"
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run --rm --network none \
        --entrypoint /bin/chown \
        -v "$work:/fixture" \
        rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 \
        -R "$(id -u):$(id -g)" /fixture/runtime /fixture/state >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
mkdir -m 0750 "$work/runtime"
mkdir -m 0700 "$work/state"
cp examples/mist.example.json "$work/runtime/mist.json"
printf '%s\n' '{"version":1,"tokens":[]}' > "$work/runtime/tokens.json"
printf '%s\n' 'packaging-smoke-mist-token' > "$work/runtime/mist-api-token"
printf '%s\n' '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > "$work/runtime/audit-hmac.key"
chmod 0640 "$work/runtime/mist.json"
chmod 0600 "$work/runtime/tokens.json" "$work/runtime/mist-api-token" "$work/runtime/audit-hmac.key"

# The release identity is numeric; prepare bind mounts without broad host chmod.
docker run --rm --network none \
    --entrypoint /bin/chown \
    -v "$work:/fixture" \
    rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 \
    -R 65532:65532 /fixture/runtime /fixture/state

docker run -d --name "$name" \
    --user 65532:65532 \
    --read-only \
    --network host \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 128 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    -v "$work/runtime:/etc/rustmistmcp:ro" \
    -v "$work/state:/var/lib/rustmistmcp:rw" \
    "$image" >/dev/null

http_status=
for _attempt in $(seq 1 30); do
    if [[ $(docker inspect --format '{{.State.Running}}' "$name") != true ]]; then
        break
    fi
    http_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --max-time 1 http://127.0.0.1:30030/mcp || true)
    [[ $http_status == 401 ]] && break
    sleep 1
done
logs=$(docker logs "$name" 2>&1 || true)
[[ $(docker inspect --format '{{.State.Running}}' "$name") == true ]] || {
    printf 'OCI process exited during startup:\n%s\n' "$logs" >&2
    exit 1
}
[[ $http_status == 401 ]] || {
    printf 'expected anonymous HTTP 401 from loopback listener, got %s:\n%s\n' "${http_status:-none}" "$logs" >&2
    exit 1
}
if grep -Fq 'packaging-smoke-mist-token' <<<"$logs"; then
    printf '%s\n' 'Mist credential leaked into container logs' >&2
    exit 1
fi
printf '%s\n' 'OCI mounted startup: PASS (loopback HTTP anonymous request rejected with 401)'
