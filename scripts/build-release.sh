#!/usr/bin/env bash
# Build one deterministic, credential-free release archive from a clean tree.
set -euo pipefail
umask 022

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if [[ ${RUSTMISTMCP_CI_SOURCE_VERIFIED:-0} == 1 ]]; then
    [[ ${RUSTMISTMCP_COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || {
        printf '%s\n' 'CI source mode requires RUSTMISTMCP_COMMIT as exactly 40 lowercase hex' >&2
        exit 1
    }
    [[ ${SOURCE_DATE_EPOCH:-} =~ ^[0-9]+$ ]] || {
        printf '%s\n' 'CI source mode requires numeric SOURCE_DATE_EPOCH' >&2
        exit 1
    }
    source_commit=$RUSTMISTMCP_COMMIT
elif [[ ${RUSTMISTMCP_ALLOW_DIRTY:-0} != 1 ]] &&
    [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
        printf '%s\n' 'refusing to build from a dirty tree (set RUSTMISTMCP_ALLOW_DIRTY=1 to override)' >&2
        exit 1
else
    source_commit=$(git rev-parse HEAD)
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
fi

target=${1:-$(rustc -vV | sed -n 's/^host: //p')}
cargo_version=$(awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version = / {
        gsub(/"/, "", $3); print $3; exit
    }
' Cargo.toml)
[[ -n $cargo_version ]] || { printf '%s\n' 'could not determine package version' >&2; exit 1; }
version=${RUSTMISTMCP_RELEASE_VERSION:-$cargo_version}
if [[ $version != "$cargo_version" ]]; then
    rc_suffix=${version#"$cargo_version-rc"}
    [[ $version == "$cargo_version-rc$rc_suffix" && $rc_suffix =~ ^[1-9][0-9]*$ ]] || {
        printf 'release version must equal Cargo version or a matching RC: Cargo=%s release=%s\n' "$cargo_version" "$version" >&2
        exit 1
    }
fi

export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/usr/src/rustmistmcp"

# Build unless the caller supplied a binary.
#
# Repackaging a released version on a workstation is usually wrong: glibc is
# forward-incompatible, so a binary linked against a newer glibc than the target
# container will not start there, and it fails at service start after the old
# binary has been replaced. Packaging a release therefore means packaging the
# binary CI built, taken from the release image.
#
# Without this flag the only way to do that was to hand-write BUILD-INFO, which
# invites inventing a `rustc` and a `commit` that never built anything. BUILD-INFO
# is provenance; a fabricated one is worse than none. So when the build is
# skipped, every field that cannot be known honestly says so.
cargo_target_dir=${CARGO_TARGET_DIR:-$root/target}
if [[ $cargo_target_dir != /* ]]; then
    cargo_target_dir="$root/$cargo_target_dir"
fi

if [[ ${RUSTMISTMCP_SKIP_BUILD:-0} == 1 ]]; then
    prebuilt="$cargo_target_dir/$target/release/rustmistmcp"
    [[ -x $prebuilt ]] || {
        # The image is multi-arch; name the platform that matches $target.
        case $target in
            aarch64-unknown-linux-gnu) image_platform=linux/arm64 ;;
            *) image_platform=linux/amd64 ;;
        esac
        printf '%s\n' \
            "RUSTMISTMCP_SKIP_BUILD=1 but $prebuilt is missing or not executable." \
            'Place the CI-built binary there first, e.g. from the release image:' \
            "  docker create --platform $image_platform --name mx ghcr.io/mechubsec/rustmistmcp:<version>" \
            "  docker cp mx:/usr/local/bin/rustmistmcp $prebuilt" \
            '  docker rm mx' >&2
        exit 1
    }
    # Validate that the supplied binary matches the release being packaged.
    # A stale or wrong binary produces a confidently mislabeled archive.
    # Check architecture first (file-based, does not exec) so a cross-arch binary
    # is diagnosed as such rather than failing at --version with a misleading error.
    binary_arch=$(file "$prebuilt" | grep -oE 'x86-64|aarch64|ARM aarch64' || printf 'unknown')
    case $target in
        x86_64-*) expected_arch='x86-64' ;;
        aarch64-*) expected_arch='aarch64|ARM aarch64' ;;
        *) expected_arch='.*' ;;
    esac
    if ! printf '%s\n' "$binary_arch" | grep -qE "^($expected_arch)$"; then
        printf 'binary architecture mismatch: binary is %s, target is %s\n' \
            "$binary_arch" "$target" >&2
        exit 1
    fi
    binary_version=$("$prebuilt" --version 2>/dev/null | awk '{print $2}') || {
        printf '%s\n' "RUSTMISTMCP_SKIP_BUILD=1 but $prebuilt --version failed" >&2
        exit 1
    }
    [[ $binary_version == "$cargo_version" ]] || {
        printf 'binary version mismatch: binary reports %s, packaging %s (Cargo.toml)\n' \
            "$binary_version" "$cargo_version" >&2
        exit 1
    }
    printf '%s\n' "skipping cargo build: packaging the existing $prebuilt"
else
    cargo build --release --locked --bin rustmistmcp --target "$target"
fi

out=${RUSTMISTMCP_DIST_DIR:-$root/dist}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
name="rustmistmcp-v${version}-${target}"
payload="$stage/$name"
mkdir -p "$payload/bin" "$payload/docs" "$payload/packaging/systemd" "$payload/packaging/lxc" "$payload/packaging/examples"
install -m 0755 "$cargo_target_dir/$target/release/rustmistmcp" "$payload/bin/rustmistmcp"
install -m 0644 LICENSE README.md "$payload/"
install -m 0644 docs/OPERATIONS.md docs/PACKAGING_ACCEPTANCE.md "$payload/docs/"
install -m 0644 packaging/systemd/rustmistmcp.service packaging/systemd/rustmistmcp.sysusers packaging/systemd/rustmistmcp.tmpfiles "$payload/packaging/systemd/"
install -m 0755 packaging/lxc/install.sh "$payload/packaging/lxc/"
install -m 0644 packaging/examples/mist.example.json packaging/examples/tokens.example.json "$payload/packaging/examples/"
binary_sha256=$(sha256sum "$payload/bin/rustmistmcp" | awk '{print $1}')

# `rustc` and `commit` record which compiler and source revision produced this
# binary. When the build was skipped, the local toolchain and checkout did not
# produce it, and naming them here would be a false provenance claim - so say
# what is actually known instead. The sha256 is computed from the real bytes
# either way, which is the field that lets someone check what they are holding.
if [[ ${RUSTMISTMCP_SKIP_BUILD:-0} == 1 ]]; then
    rustc_field="unknown (binary supplied prebuilt; not compiled by this script)"
    commit_field="unknown (binary supplied prebuilt; source revision not verified)"
    # source_date_epoch is also derived from the local HEAD's commit time, so it
    # would be equally unknowable, but the caller may have set it explicitly via
    # RUSTMISTMCP_CI_SOURCE_VERIFIED mode. Preserve it if set; mark unknown if not.
    if [[ ${RUSTMISTMCP_CI_SOURCE_VERIFIED:-0} != 1 ]]; then
        source_date_field="unknown (binary supplied prebuilt)"
    else
        source_date_field="$SOURCE_DATE_EPOCH"
    fi
else
    rustc_field="$(rustc -V)"
    commit_field="$source_commit"
    source_date_field="$SOURCE_DATE_EPOCH"
fi

printf 'version=%s\ncargo_version=%s\ntarget=%s\ncommit=%s\nrustc=%s\nsource_date_epoch=%s\nbinary_sha256=%s\n' \
    "$version" "$cargo_version" "$target" "$commit_field" "$rustc_field" "$source_date_field" "$binary_sha256" > "$payload/BUILD-INFO"

mkdir -p "$out"
archive="$out/$name.tar.gz"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - "$name" | gzip -n > "$archive"
(cd "$out" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
printf '%s\n' "$archive"
