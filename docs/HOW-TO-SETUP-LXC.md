# How to set up a rustmistmcp LXC from scratch

Builds one Proxmox LXC running `rustmistmcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

Never point a lab-mode server at production. It says so itself at startup, in
a `WARN`.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The credentials the server will use.** A Mist API token
  (`/etc/rustmistmcp/mist-api-token`), a Mist profile
  (`/etc/rustmistmcp/mist.json`), an audit HMAC key, and a `tokens.json` bearer
  store. Building the container is the easy part; these are the part you cannot
  regenerate. If you are rebuilding an existing rig, back them up first — see
  [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc.
Pin by **immutable digest** rather than a mutable tag, so republishing the tag
does not silently change what you package.

**Important:** extract directly to the **gitignored target path** the skip-build
branch reads, never to the repo root — an untracked file at the root dirties
the tree, and the packager refuses a dirty tree before `RUSTMISTMCP_SKIP_BUILD`
is honored:

```bash
# Obtain the digest for the version you want:
#   docker pull ghcr.io/mechubsec/rustmistmcp:0.5.0
#   docker inspect ghcr.io/mechubsec/rustmistmcp:0.5.0 --format='{{index .RepoDigests 0}}'
# Then extract the binary directly to the target path:
cd /path/to/rustmistmcp
target_path=${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-gnu/release
mkdir -p "$target_path"
docker create --name mx ghcr.io/mechubsec/rustmistmcp@sha256:<verified-64-hex-digest>
docker cp mx:/usr/local/bin/rustmistmcp "$target_path/rustmistmcp"
docker rm mx
chmod 0755 "$target_path/rustmistmcp"
```

On the workstation, glibc is 2.44; in the Debian 13 container, it is 2.41.
Forward-incompatible means the 2.44-linked binary will not load against 2.41.

## 2. Package the release

`scripts/build-release.sh` builds the tarball from the binary you just extracted:

```bash
RUSTMISTMCP_SKIP_BUILD=1 scripts/build-release.sh
# >> Wrote dist/rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
```

`RUSTMISTMCP_SKIP_BUILD=1` tells the packager to use the existing binary instead
of compiling. When the build is skipped, `BUILD-INFO` records
`rustc=unknown (binary supplied prebuilt; not compiled by this script)` rather
than naming a local toolchain that compiled nothing. The sha256 is still
computed from the real bytes.

> **Why BUILD-INFO must not be hand-written.** BUILD-INFO is the provenance
> record. A fabricated one — invented `rustc`, `commit`, and timestamp to
> satisfy the installer — is worse than none, because it claims a lineage that
> does not exist. During the 2026-09-07 rebuild there was no supported way to
> package a CI-built binary, so a BUILD-INFO was forged. That gap is now closed.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 618 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-twoperson-mist \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.10/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;twoperson"

pct start 618
```

512 MB and one core is enough. 4 GB rootfs. The tags matter: `disposable` is
what marks a guest as safe to destroy, and the fleet's own safety rules key on
it.

For a lab-mode rig, change the VMID, hostname, IP, and the final tag to
`labmode`:

```bash
pct create 619 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-labmode-mist \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.11/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;labmode"

pct start 619
```

Both bind port 30030.

## 4. Install

`install.sh` requires two arguments: the tarball and its `.sha256` sidecar. It
also requires an environment variable attesting that the host is unprivileged
with nesting enabled, which the installer cannot verify from inside the
container. Push both files under their original basenames (the installer
validates against the release naming contract). **Verify the archive checksum
BEFORE extracting** to ensure arbitrary archive code never executes:

```bash
pct push 618 dist/rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz /tmp/rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
pct push 618 dist/rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256 /tmp/rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256

pct exec 618 -- bash -lc '
  cd /tmp
  # Verify checksum BEFORE extracting anything
  sha256sum -c rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256 || exit 1
  tar xzf rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
  cd rustmistmcp-*/
  RUSTMISTMCP_LXC_HOST_PROOF=unprivileged=1,nesting=1 bash ./packaging/lxc/install.sh /tmp/rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz /tmp/rustmistmcp-v0.5.0-x86_64-unknown-linux-gnu.tar.gz.sha256
'
```

`install.sh` creates the `rustmistmcp` service user, installs the binary and the
unit, and stops there. **The service will not start yet** — it has no
credentials, and it says so.

## 5. Configuration and credentials

Four credential files are required, and all must be present and correctly
permissioned **before** the first start. The service checks them one at a time
at startup, so getting this wrong costs you one restart per file.

```bash
pct push 618 /path/to/mist.json              /etc/rustmistmcp/mist.json
pct push 618 /path/to/mist-api-token         /etc/rustmistmcp/mist-api-token
pct push 618 /path/to/audit-hmac.key         /etc/rustmistmcp/audit-hmac.key
pct push 618 /path/to/tokens.json            /var/lib/rustmistmcp/tokens.json
```

Then fix ownership and modes:

```bash
pct exec 618 -- bash -lc '
    chown root:rustmistmcp /etc/rustmistmcp/mist.json
    chmod 0640 /etc/rustmistmcp/mist.json

    chown rustmistmcp:rustmistmcp /etc/rustmistmcp/mist-api-token
    chmod 0600 /etc/rustmistmcp/mist-api-token

    chown rustmistmcp:rustmistmcp /etc/rustmistmcp/audit-hmac.key
    chmod 0600 /etc/rustmistmcp/audit-hmac.key

    chown rustmistmcp:rustmistmcp /var/lib/rustmistmcp/tokens.json
    chmod 0600 /var/lib/rustmistmcp/tokens.json

    install -d -o rustmistmcp -g rustmistmcp -m 0700 /var/lib/rustmistmcp
'
```

**A real trap: `tokens.json` moved paths.** Older rigs kept `tokens.json` in
`/etc/rustmistmcp/`. It now lives in `/var/lib/rustmistmcp/`. A drop-in restored
from an older backup may still point `--tokens-file` at the old path, and the
service will fail to start. Check the drop-in and fix the path if needed.

## 6. The site drop-in

The shipped unit binds `127.0.0.1` and is deliberately conservative. Site
configuration goes in a drop-in, which keeps the shipped unit replaceable:

```bash
pct exec 618 -- bash -lc 'mkdir -p /etc/systemd/system/rustmistmcp.service.d'
```

`install.sh` does **not** create this directory, because a drop-in is a site
decision.

For the **two-person** rig:

`/etc/systemd/system/rustmistmcp.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustmistmcp \
    --device-mapping /etc/rustmistmcp/mist.json \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30030 \
    --tokens-file /var/lib/rustmistmcp/tokens.json \
    --allow-insecure-bind \
    --allowed-host 192.0.2.10 \
    --allowed-host test-twoperson-mist:30030 \
    --allowed-origin http://192.0.2.10:30030 \
    --allowed-origin http://test-twoperson-mist:30030 \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac \
    --audit-hmac-key-file /etc/rustmistmcp/audit-hmac.key
```

For the **lab-mode** rig, add `--lab-mode`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustmistmcp \
    --device-mapping /etc/rustmistmcp/mist.json \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30030 \
    --tokens-file /var/lib/rustmistmcp/tokens.json \
    --allow-insecure-bind \
    --allowed-host 192.0.2.11 \
    --allowed-host test-labmode-mist:30030 \
    --allowed-origin http://192.0.2.11:30030 \
    --allowed-origin http://test-labmode-mist:30030 \
    --lab-mode \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac \
    --audit-hmac-key-file /etc/rustmistmcp/audit-hmac.key
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one. **That single `--lab-mode` flag is the whole difference** between the
two rigs.

**CRITICAL:** The empty `ExecStart=` clears the shipped command **in its
entirety**, including every flag in it. Any flag you do not repeat in the
replacement is silently gone. Both drop-ins above restore the full audit
configuration — `--audit-redact` and `--audit-hmac-key-file` — that the
shipped unit carries. Losing those flags leaves audit redaction disabled and
the HMAC key unused, so `host`, `name`, and `device` fields are written
unhashed. See issue #78.

`--allowed-host` and `--allowed-origin` serve **different purposes** and are
configured independently:

- **`--allowed-host`** lists the server authorities clients dial (IP addresses
  and DNS names). This validates the HTTP `Host` header. A mismatch returns
  **421 MISDIRECTED_REQUEST** with `Host '<host>' is not allowed`.

- **`--allowed-origin`** lists the trusted browser application origins that
  call this server. This validates the `Origin` header sent by browsers. A
  mismatch returns **403 FORBIDDEN** with `Origin '<origin>' is not allowed`.
  Clients that send no `Origin` header (curl, non-browser MCP clients) are
  unaffected by this check.

**These drop-ins bind plaintext for convenience** (`--host 0.0.0.0` with
`--allow-insecure-bind`) because they are **disposable test rigs on a trusted
lab network**. This repository's CLAUDE.md requires TLS plus exact Host/Origin
policy for any external HTTP deployment, and that rule governs every
non-disposable deployment — use `--tls-cert` and `--tls-key` with `https://`
origins for production or any rig that leaves the lab. The origin scheme must
match the server's TLS configuration: plaintext uses `http://` origins; HTTPS
requires `https://` origins — browsers block HTTPS→HTTP calls as active mixed
content.

A non-loopback `--host` requires at least one `--allowed-origin` to start,
even if no browser clients exist yet. The drop-ins above use documentation
addresses and `http://` schemes matching the plaintext binding — for TLS
deployments, switch to `https://` origins and provide valid certificates.

Why site config belongs in a drop-in: the shipped unit carries the seccomp
posture. Replacing it wholesale silently loses that on upgrade.

Then:

```bash
pct exec 618 -- systemctl daemon-reload
pct exec 618 -- systemctl enable --now rustmistmcp.service
```

## 7. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 618 -- /usr/local/bin/rustmistmcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 618 -- systemctl show rustmistmcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 618 -- grep -l SystemCallErrorNumber /etc/systemd/system/rustmistmcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 618 -- systemctl show -p MainPID --value rustmistmcp.service)
pct exec 618 -- grep -E '^Seccomp' /proc/$pid/status                                    # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.0.2.10:30030/mcp \
     -H 'content-type: application/json' -d '{}'                                        # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

Checking `SystemCallErrorNumber` matters. Without it a denied syscall raises
SIGSYS and kills the process mid-request instead of returning `EPERM`.

**Note on the curl check:** `curl` is not installed in the base Debian 13
template. Run this check from the Proxmox host, not from inside the container.

## Troubleshooting

**Service fails to start with `non-loopback bind '0.0.0.0' requires at least one --allowed-origin`**

The drop-in binds `--host 0.0.0.0` but is missing `--allowed-origin` flags.
A non-loopback listener requires at least one `--allowed-origin` to start,
even if no browser clients exist yet. Add one or more browser application
origins (e.g., `http://console.example.org` for plaintext, `https://...` with
TLS configured), not the server's own address.

**Requests fail with `421 MISDIRECTED_REQUEST` and `Host '<host>' is not allowed`**

The client is dialing an address that is not in the `--allowed-host` list.
Add the server authority the client actually dials — IP address or DNS name,
with port if non-standard (e.g., `192.0.2.10`, `test-twoperson-mist:30030`).

**Browser requests fail with `403 FORBIDDEN` and `Origin '<origin>' is not allowed`**

The browser is running an application whose origin is not in the
`--allowed-origin` list. Add the browser application's origin with scheme and
port matching the server's TLS configuration (e.g., `http://console.example.org`
for plaintext, `https://...` with `--tls-cert`/`--tls-key`). Non-browser clients
(curl, MCP CLI) are unaffected — this check applies only when an `Origin` header
is present.

**Audit log contains unhashed device/host/name fields**

The drop-in is missing `--audit-redact` and `--audit-hmac-key-file`. When you
clear `ExecStart=` to replace it, you discard the **entire** shipped command,
including all audit flags. Both must be restored in the replacement — see the
drop-in examples above and issue #78.

## 8. Stop the rig

Test rigs here are stopped by default; started only when needed, stopped again
at completion.

```bash
# Use shutdown, not stop: the service persists change-set state to disk, and a
# process killed mid-write leaves non-terminal operations that block the device.
pct shutdown 618
pct shutdown 619
```

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 618
cp -a /var/lib/lxc/618/rootfs/etc/rustmistmcp        /root/backup-618/
cp -a /var/lib/lxc/618/rootfs/var/lib/rustmistmcp    /root/backup-618/
cp -a /var/lib/lxc/618/rootfs/etc/systemd/system/rustmistmcp.service.d /root/backup-618/
pct config 618 > /root/backup-618/pct-config.txt
pct unmount 618
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you
will want to reproduce.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.

**Before restoring, verify the drop-in's `--tokens-file` points at
`/var/lib/rustmistmcp/tokens.json`, not `/etc/rustmistmcp/tokens.json`.** Older
rigs used the `/etc` path. Restoring from an old backup with a stale path will
fail.
