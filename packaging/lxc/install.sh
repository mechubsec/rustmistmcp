#!/usr/bin/env bash
# Install a verified rustmistmcp release archive in Debian 13 LXC only.
set -euo pipefail

die() {
    printf 'rustmistmcp installer: %s\n' "$*" >&2
    exit 1
}

# Prove whether systemd's IPAddress* filters actually attach here, rather than
# assuming the unit's declaration means anything. systemd implements them with
# cgroup eBPF and FAILS OPEN when it cannot load the program -- typical in an
# unprivileged LXC without host delegation -- so the unit can declare a full
# egress policy while enforcing none of it. `systemd-analyze security` reads the
# declaration and cannot tell the difference.
#
# Informational by default: a runtime that withholds BPF is a legitimate
# deployment, and the operator needs to know rather than be blocked. Set
# RUSTMISTMCP_REQUIRE_EGRESS_FILTER=1 to make a non-enforcing host fatal.
egress_probe_unknown() {
    local require=$1 reason=$2
    printf '%s\n' "egress filter: UNKNOWN ($reason)" >&2
    # Strict mode must not accept what it could not measure. An unmeasurable
    # host is exactly as unguaranteed as a non-enforcing one.
    [[ "$require" == 1 ]] \
        && die 'RUSTMISTMCP_REQUIRE_EGRESS_FILTER=1 and egress enforcement could not be determined'
    return 0
}

report_egress_enforcement() {
    local require=${RUSTMISTMCP_REQUIRE_EGRESS_FILTER:-0}
    local probe_unit="rustmistmcp-egress-probe-$$"
    local unit_path="/etc/systemd/system/rustmistmcp.service"

    if ! command -v systemd-run >/dev/null; then
        egress_probe_unknown "$require" 'systemd-run unavailable; cannot probe'
        return $?
    fi

    # Two independent conditions have to hold, and conflating them is how the
    # previous version overstated its result:
    #   1. the host can attach the cgroup BPF program at all, and
    #   2. the *installed* unit actually declares an egress policy.
    # A transient probe only establishes (1). If the installer preserved a
    # customized unit with no IPAddressDeny, (1) alone would still have printed
    # ENFORCED and satisfied the strict flag over a service filtering nothing.
    local counters=''
    if systemd-run --quiet --collect --unit="$probe_unit" \
        --property=IPAccounting=yes --property=RemainAfterExit=yes \
        /bin/true >/dev/null 2>&1
    then
        counters=$(systemctl show "$probe_unit.service" -p IPEgressBytes --value 2>/dev/null || printf '')
        systemctl stop "$probe_unit.service" >/dev/null 2>&1 || true
        systemctl reset-failed "$probe_unit.service" >/dev/null 2>&1 || true
    else
        egress_probe_unknown "$require" 'probe unit would not start; run as root to determine'
        return $?
    fi

    if [[ -z "$counters" || "$counters" == '[no data]' ]]; then
        printf '%s\n' \
            'egress filter: NOT ENFORCED' \
            '  systemd cannot attach its cgroup BPF program here, so the IPAddressAllow/' \
            '  IPAddressDeny lines in rustmistmcp.service have no effect. This is normal in' \
            '  an unprivileged LXC. The unit still applies every other sandbox directive.' \
            '  Move the control outward to whatever layer sees this workload'"'"'s packets --' \
            '  guest firewall, host nftables, NetworkPolicy, or cloud security group -- and' \
            '  deny 169.254.0.0/16 plus the local subnet except your resolver, allow 443 out.' \
            '  docs/OPERATIONS.md, "Enforcing it where systemd cannot", has the per-runtime' \
            '  mechanism and a verification command.' >&2
        [[ "$require" == 1 ]] \
            && die 'RUSTMISTMCP_REQUIRE_EGRESS_FILTER=1 and systemd IP filtering is not enforced here'
        return 0
    fi

    # (1) holds. Now (2): does the unit that was actually installed carry a
    # policy for the kernel to enforce?
    if ! grep -Eq '^[[:space:]]*IPAddressDeny[[:space:]]*=[[:space:]]*[^[:space:]]' "$unit_path"; then
        printf '%s\n' \
            'egress filter: NO POLICY' \
            "  This host can enforce systemd IP filtering, but $unit_path declares no" \
            '  IPAddressDeny. A preserved customized unit overrides the packaged policy;' \
            '  re-install with RUSTMISTMCP_FORCE_UNIT=1 or add the directives by hand.' >&2
        [[ "$require" == 1 ]] \
            && die 'RUSTMISTMCP_REQUIRE_EGRESS_FILTER=1 and the installed unit declares no egress policy'
        return 0
    fi

    printf '%s\n' 'egress filter: ENFORCED'
    return 0
}

require_safe_live_secret() {
    local path=$1
    [[ ! -L $path ]] || die "live secret path must not be a symlink: $path"
    [[ ! -e $path || -f $path ]] ||
        die "existing live secret path must be a regular file: $path"
}

service_user=rustmistmcp

# Place a freshly generated secret file. The content is built in a private temp
# file and moved into place with install(1), which replaces rather than follows
# anything already at the destination.
install_new_secret() {
    local dest=$1 content=$2 tmp
    require_safe_live_secret "$dest"
    tmp=$(mktemp)
    printf '%s\n' "$content" > "$tmp"
    install -m 0600 -o "$service_user" -g "$service_user" "$tmp" "$dest"
    rm -f "$tmp"
}

# Re-guard immediately before changing ownership and mode of an existing file in
# a directory the service account can write to.
secure_existing_secret() {
    local path=$1
    [[ -e $path || -L $path ]] || return 0
    require_safe_live_secret "$path"
    chown -h "$service_user:$service_user" -- "$path"
    require_safe_live_secret "$path"
    chmod 0600 -- "$path"
}

usage() {
    printf '%s\n' \
        'usage: install.sh [--validate-only] /path/to/rustmistmcp-v<VERSION>-<TARGET>.tar.gz /path/to/archive.sha256' >&2
    exit 2
}

validate_only=0
if [[ ${1:-} == --validate-only ]]; then
    validate_only=1
    shift
fi
[[ $# -eq 2 ]] || usage
archive_arg=$1
checksum_arg=$2

# Snapshot both caller-controlled inputs before reading either of them. All
# validation, listing, and extraction below uses only these private copies.
umask 077
work=$(mktemp -d)
chmod 0700 "$work"
trap 'rm -rf "$work"' EXIT
archive="$work/archive"
checksum="$work/checksum"
cp --no-dereference --archive --no-target-directory -- "$archive_arg" "$archive" ||
    die 'archive cannot be copied into the private validation directory'
cp --no-dereference --archive --no-target-directory -- "$checksum_arg" "$checksum" ||
    die 'checksum cannot be copied into the private validation directory'
[[ -f $archive && ! -L $archive && -r $archive ]] ||
    die 'private archive copy must be a readable regular file'
[[ -f $checksum && ! -L $checksum && -r $checksum ]] ||
    die 'private checksum copy must be a readable regular file'

archive_base=$(basename -- "$archive_arg")
[[ $archive_base =~ ^rustmistmcp-v[0-9][0-9A-Za-z.+~-]*-[A-Za-z0-9_][A-Za-z0-9_.-]*\.tar\.gz$ ]] ||
    die 'archive basename does not match the release naming contract'
release_root=${archive_base%.tar.gz}

# Bind one exact lowercase SHA-256 record to the requested archive basename.
mapfile -t checksum_lines < "$checksum"
[[ ${#checksum_lines[@]} -eq 1 ]] || die 'checksum sidecar must contain exactly one record'
[[ ${checksum_lines[0]} =~ ^([0-9a-f]{64})\ \ ([^/]+)$ ]] ||
    die 'checksum sidecar must be: 64 lowercase hex, two spaces, archive basename'
expected_digest=${BASH_REMATCH[1]}
sidecar_name=${BASH_REMATCH[2]}
[[ $sidecar_name == "$archive_base" ]] || die 'checksum sidecar is not bound to the requested archive'
actual_digest=$(sha256sum "$archive" | awk '{print $1}')
[[ $actual_digest == "$expected_digest" ]] || die 'archive SHA-256 does not match the sidecar'

# Validate member names, multiplicity, and types before extraction.
members_file="$work/members"
verbose_file="$work/verbose"
tar --absolute-names -tzf "$archive" > "$members_file" ||
    die 'archive cannot be listed as gzip-compressed tar'
tar --absolute-names -tvzf "$archive" > "$verbose_file" ||
    die 'archive member metadata cannot be listed'
mapfile -t members < "$members_file"
[[ ${#members[@]} -gt 0 ]] || die 'archive is empty'

expected_directories=(
    "$release_root/"
    "$release_root/bin/"
    "$release_root/docs/"
    "$release_root/packaging/"
    "$release_root/packaging/examples/"
    "$release_root/packaging/lxc/"
    "$release_root/packaging/systemd/"
)
expected_files=(
    "$release_root/BUILD-INFO"
    "$release_root/LICENSE"
    "$release_root/README.md"
    "$release_root/bin/rustmistmcp"
    "$release_root/docs/OPERATIONS.md"
    "$release_root/docs/PACKAGING_ACCEPTANCE.md"
    "$release_root/packaging/examples/mist.example.json"
    "$release_root/packaging/examples/tokens.example.json"
    "$release_root/packaging/lxc/install.sh"
    "$release_root/packaging/systemd/rustmistmcp.service"
    "$release_root/packaging/systemd/rustmistmcp.sysusers"
    "$release_root/packaging/systemd/rustmistmcp.tmpfiles"
)
declare -A expected=()
declare -A seen=()
for member in "${expected_directories[@]}" "${expected_files[@]}"; do
    expected["$member"]=1
done
for member in "${members[@]}"; do
    [[ -n $member ]] || die 'archive contains an empty member name'
    [[ $member != /* && $member != ./* && $member != ../* &&
        $member != */../* && $member != */.. && $member != */./* && $member != */. ]] ||
        die "archive contains an absolute or dot-segment path: $member"
    [[ ${expected[$member]+present} ]] || die "archive contains an unexpected member: $member"
    [[ ! ${seen[$member]+present} ]] || die "archive contains a duplicate member: $member"
    seen["$member"]=1
done
for member in "${!expected[@]}"; do
    [[ ${seen[$member]+present} ]] || die "archive is missing required member: $member"
done
while IFS= read -r metadata; do
    case ${metadata:0:1} in
        -|d) ;;
        *) die 'archive contains a link, device, or FIFO member' ;;
    esac
done < "$verbose_file"

# Extract only to a fresh temporary directory, then verify without following links.
extract_root="$work/extracted"
mkdir "$extract_root"
tar -xzf "$archive" -C "$extract_root" --no-same-owner --no-same-permissions ||
    die 'archive extraction failed'
payload="$extract_root/$release_root"
unexpected_type=$(find -P "$payload" -mindepth 1 ! -type d ! -type f -print -quit)
[[ -z $unexpected_type ]] || die "extracted payload has an unsafe object type: $unexpected_type"
for member in "${expected_directories[@]}"; do
    extracted="$extract_root/${member%/}"
    [[ -d $extracted && ! -L $extracted ]] || die "required directory is unsafe after extraction: $member"
    [[ $(realpath -e -- "$extracted") == "$extract_root/${member%/}" ]] ||
        die "required directory escapes the extraction root: $member"
done
for member in "${expected_files[@]}"; do
    extracted="$extract_root/$member"
    [[ -f $extracted && ! -L $extracted ]] || die "required file is unsafe after extraction: $member"
    [[ $(realpath -e -- "$extracted") == "$extract_root/$member" ]] ||
        die "required file escapes the extraction root: $member"
done

if (( validate_only )); then
    printf 'validated %s sha256:%s\n' "$archive_base" "$actual_digest"
    exit 0
fi

# Host mutation is allowed only after archive validation and explicit platform proof.
[[ $(id -u) -eq 0 ]] || die 'run as root inside the target LXC'
[[ -r /etc/os-release ]] || die 'cannot verify Debian release'
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || die 'installer requires Debian 13'
[[ $(systemd-detect-virt --container 2>/dev/null || true) == lxc ]] ||
    die 'installer requires an LXC guest'
[[ ${RUSTMISTMCP_LXC_HOST_PROOF:-} == 'unprivileged=1,nesting=1' ]] ||
    die 'host-side proof required: verify unprivileged=1 and features nesting=1, then set RUSTMISTMCP_LXC_HOST_PROOF=unprivileged=1,nesting=1'

# Refuse an unsafe live-secret target before the first host mutation. Repeat the
# checks immediately before secret handling to narrow the remaining race window.
require_safe_live_secret /var/lib/rustmistmcp/tokens.json
require_safe_live_secret /etc/rustmistmcp/audit-hmac.key
require_safe_live_secret /etc/rustmistmcp/mist-api-token

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates
if [[ ${RUSTMISTMCP_INSTALL_VERIFY_TOOLS:-0} == 1 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl
fi
apt-get clean
rm -rf /var/lib/apt/lists/*

install -D -m 0644 "$payload/packaging/systemd/rustmistmcp.sysusers" /usr/lib/sysusers.d/rustmistmcp.conf
install -D -m 0644 "$payload/packaging/systemd/rustmistmcp.tmpfiles" /usr/lib/tmpfiles.d/rustmistmcp.conf
systemd-sysusers
systemd-tmpfiles --create /usr/lib/tmpfiles.d/rustmistmcp.conf

install -D -o root -g root -m 0755 "$payload/bin/rustmistmcp" /usr/local/bin/rustmistmcp

# Remove stale mecmcp.conf if present. Stop shipping it per rustmistmcp#44.
if [[ -e /etc/systemd/journald.conf.d/mecmcp.conf ]]; then
    rm -f /etc/systemd/journald.conf.d/mecmcp.conf
fi
if [[ ! -e /etc/systemd/system/rustmistmcp.service || ${RUSTMISTMCP_FORCE_UNIT:-0} == 1 ]]; then
    install -D -m 0644 "$payload/packaging/systemd/rustmistmcp.service" /etc/systemd/system/rustmistmcp.service
fi

# Examples are non-live. Live config, credentials, state, and customized units are preserved.
install -D -m 0644 "$payload/packaging/examples/mist.example.json" /etc/rustmistmcp/mist.example.json
install -D -m 0644 "$payload/packaging/examples/tokens.example.json" /etc/rustmistmcp/tokens.example.json
require_safe_live_secret /var/lib/rustmistmcp/tokens.json
require_safe_live_secret /etc/rustmistmcp/audit-hmac.key
require_safe_live_secret /etc/rustmistmcp/mist-api-token
# tokens.json moved from /etc/rustmistmcp to /var/lib/rustmistmcp (#42).
#
# Create an empty store ONLY when no legacy store exists. The runtime prefers an
# existing primary, so writing an empty file here while the live tokens are still
# at /etc/rustmistmcp/tokens.json would shadow them: the service starts and
# rejects every existing bearer token. A silent auth wipe on upgrade is worse
# than a refusal.
#
# The file is never copied automatically — that would leave a duplicate secret
# behind, which is what the stale-secret scan exists to flag.
if [[ ! -e /var/lib/rustmistmcp/tokens.json && ! -L /var/lib/rustmistmcp/tokens.json ]]; then
    if [[ -e /etc/rustmistmcp/tokens.json ]]; then
        printf '%s\n' '>> Not creating /var/lib/rustmistmcp/tokens.json: a token store already'
        printf '%s\n' '>> exists at /etc/rustmistmcp/tokens.json. The server reads it via the'
        printf '%s\n' '>> legacy fallback and warns. Migrate it deliberately, then remove it:'
        printf '%s\n' '>>   install -m 0600 -o rustmistmcp -g rustmistmcp'
        printf '%s\n' '>>     /etc/rustmistmcp/tokens.json /var/lib/rustmistmcp/tokens.json'
        printf '%s\n' '>>   rm /etc/rustmistmcp/tokens.json'
    else
        install_new_secret /var/lib/rustmistmcp/tokens.json '{"version":1,"tokens":[]}'
    fi
fi

# Existing secrets are re-guarded right before ownership and mode changes.
secure_existing_secret /var/lib/rustmistmcp/tokens.json
secure_existing_secret /etc/rustmistmcp/audit-hmac.key
secure_existing_secret /etc/rustmistmcp/mist-api-token

systemctl daemon-reload
systemctl restart systemd-journald
report_egress_enforcement
printf '%s\n' 'Installed rustmistmcp without enabling it.'
printf '%s\n' 'Next: configure the live Mist profile/credentials, mint a grantless bearer token with rustmistmcp token add, configure journal forwarding, then enable and start rustmistmcp.'
