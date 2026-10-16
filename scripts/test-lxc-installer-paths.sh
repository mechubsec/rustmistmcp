#!/usr/bin/env bash
# Behavioral tests for the installer's secret-file helpers: unsafe existing
# paths are refused and never written, chowned or chmodded through.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
installer="$root/packaging/lxc/install.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

helpers="$work/helpers.sh"
{
    printf '%s\n' 'die() { printf "%s\n" "$*" >&2; exit 1; }'
    sed -n '/^require_safe_live_secret() {/,/^}/p' "$installer"
    sed -n '/^install_new_secret() {/,/^}/p' "$installer"
    sed -n '/^secure_existing_secret() {/,/^}/p' "$installer"
} > "$helpers"
grep -q '^install_new_secret()' "$helpers" || { echo 'helper extraction failed' >&2; exit 1; }
grep -q '^secure_existing_secret()' "$helpers" || { echo 'helper extraction failed' >&2; exit 1; }

me=$(id -un)
canary="$work/canary"
printf 'canary\n' > "$canary"
chmod 0644 "$canary"

run() {
    bash -c 'set -euo pipefail; source "$1"; service_user=$2; shift 2; "$@"' _ "$helpers" "$me" "$@"
}

expect_refused() {
    local label=$1
    shift
    if run "$@" >/dev/null 2>&1; then
        printf 'expected refusal: %s\n' "$label" >&2
        exit 1
    fi
    if [[ $(cat "$canary") != canary || $(stat -c %a "$canary") != 644 ]]; then
        printf 'canary touched: %s\n' "$label" >&2
        exit 1
    fi
}

for fn in install_new_secret secure_existing_secret; do
    args=()
    [[ $fn == install_new_secret ]] && args=('{}')

    ln -s "$work/missing-target" "$work/dangling"
    expect_refused "$fn dangling" "$fn" "$work/dangling" "${args[@]}"
    [[ ! -e $work/missing-target ]] || { echo 'dangling target created' >&2; exit 1; }
    rm -f "$work/dangling"

    ln -s "$canary" "$work/live"
    expect_refused "$fn symlink" "$fn" "$work/live" "${args[@]}"
    rm -f "$work/live"

    mkdir "$work/dir"
    expect_refused "$fn directory" "$fn" "$work/dir" "${args[@]}"
    rmdir "$work/dir"
done

run install_new_secret "$work/fresh" '{"v":1}'
[[ $(stat -c %a "$work/fresh") == 600 && $(cat "$work/fresh") == '{"v":1}' ]] ||
    { echo 'fresh secret wrong' >&2; exit 1; }
chmod 0644 "$work/fresh"
run secure_existing_secret "$work/fresh"
[[ $(stat -c %a "$work/fresh") == 600 ]] || { echo 'mode not tightened' >&2; exit 1; }
run secure_existing_secret "$work/absent"
echo 'installer path tests passed'
