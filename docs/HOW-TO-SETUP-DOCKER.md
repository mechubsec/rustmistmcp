# How to run rustmistmcp in Docker

Runs the server as a container in either **lab mode** or **two-person** mode.
Written from a working setup built on 2026-09-07: every command here was run,
and the failures that occurred are in [Troubleshooting](#troubleshooting) with
their exact error text.

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

The server announces lab mode at startup, as a `WARN`:

```
lab mode enabled: change sets are approved on creation with no second principal.
Records carry approval_waiver=lab-mode. Do not run this against production devices.
```

If you see that line and did not intend it, stop and fix the flag.

## ENTRYPOINT and CMD split

The published image splits arguments between `ENTRYPOINT` and `CMD` so that
security-relevant configuration survives operator overrides.

**ENTRYPOINT** carries what must always hold — config paths, credentials, and
security-relevant flags:

```
--device-mapping /etc/rustmistmcp/mist.json
--tokens-file /var/lib/rustmistmcp/tokens.json
--audit-format json
--audit-redact devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac
--audit-hmac-key-file /var/lib/rustmistmcp/audit-hmac.key
```

If `/var/lib/rustmistmcp/audit-hmac.key` is absent or empty on startup, the
binary generates one itself (mode 0600, from OS entropy) and never rotates an
existing non-empty key. This closes the gap where a container that never had
a key mounted ran with a constant, predictable HMAC key. Mount a writable
volume at `/var/lib/rustmistmcp` so the generated key persists across
container restarts — a fresh key on every restart makes every prior audit
record's HMAC unverifiable.

**CMD** carries only operator-tunable flags — bind address, port, transport:

```
--transport streamable-http --host 127.0.0.1 --port 30030
```

Docker **replaces CMD entirely** when you pass arguments, but **appends to
ENTRYPOINT**. The image binds `127.0.0.1` by default, so real deployments pass
at least `--host` — that replaces the CMD flags (`--transport`, `--host`,
`--port`) but the audit configuration in ENTRYPOINT survives.

**Before v0.3.1** (fixed in #78), all flags lived in `CMD`, so any `--host`
override silently lost the audit configuration. Measured on the published 0.3.0
image:

```
image default CMD                    -> 4 audit-related arguments
container started with any own args  -> 0 audit-related arguments
```

The server started and served normally; the audit log was simply **unkeyed and
unredacted** from then on, with no warning. **Pseudonymous redaction**
of identifying fields — device names, hosts, and commands — was written
in plaintext. The HMAC flags provide pseudonymity (making fields unlinkable to
their source without the key), not tamper-evidence: records can still be
deleted, reordered, or replaced undetected because nothing signs or hash-chains
whole records.

This is tracked in [issue #78](https://github.com/mechubsec/rustmistmcp/issues/78).
Until it is fixed, **every example in this document passes the audit flags
explicitly**. Copy them. A reader who omits them loses the audit pseudonymity
this server is built to provide.

Verify your running container has the audit arguments:

```bash
docker inspect <container> --format '{{join .Args " "}}' | grep audit
```

If that prints nothing, you dropped them. Stop the container and fix the
command.

## 1. Prepare host paths

```bash
mkdir -p mist-docker
cd mist-docker
```

**`mist.json`** — the Mist profile. Note that the **credential is not in it**;
it is referenced by `credential`, either a mounted file or an environment
variable:

```json
{
  "version": 1,
  "endpoint": "https://api.mist.com/",
  "credential": {
    "type": "file",
    "path": "/etc/rustmistmcp/mist-api-token"
  },
  "allowed_orgs": [
    "00000000-0000-0000-0000-000000000000"
  ]
}
```

A stdio deployment that injects the token as an environment variable instead
of a mounted file (for example the MCP Toolkit registry's `config.secrets`)
uses `{"type": "env", "name": "MIST_API_TOKEN"}` instead — the variable is
read fresh at startup, never written to this file or to argv.

Replace `endpoint` with your region's Mist API endpoint (`api.mist.com`,
`api.eu.mist.com`, or `api.gc1.mist.com`) and populate `allowed_orgs` with
the org UUIDs this server may reach.

**`mist-api-token`** — the outbound Mist API token. Create one from the Mist
web UI (*Organization > Settings > API Tokens*) with appropriate privileges.
This file contains the token in plain text. Read it without echo to keep it
out of shell history:

```bash
read -sp 'Mist API token: ' token && printf '%s' "$token" > mist-api-token && unset token
```

**`audit-hmac.key`** — the HMAC key for pseudonymous audit redaction. Generate a
random key:

```bash
openssl rand -hex 32 > audit-hmac.key
```

This step is now optional: if you skip it, the server generates a key itself
on first run (see the ENTRYPOINT note above). Generate it yourself only if you
want control over the exact moment a key is created, or want to reuse the same
key across a redeploy without first copying it out of a running container.

**Mint a bearer token.** The binary can do this on the host — no container
needed, but note the **`-f` flag** because it defaults to `devices.json`, not
`mist.json`:

```bash
rustmistmcp token add --tokens-file ./tokens.json \
    --name my-client --devices '*' --tools '*' -f ./mist.json
```

The secret prints **once** and is stored hashed. `--tools '*'` resolves to
read-only tools only; write tools must be named explicitly, so a wildcard token
calling `plan_mist_change` gets `insufficient_scope`. That is deliberate.

Then lock the modes down:

```bash
chmod 0600 mist.json mist-api-token audit-hmac.key tokens.json
```

## 2. Ownership: two options

The container process is UID 65532 and must read the config and write the state
directory.

**For a real deployment**, give it ownership:

```bash
sudo chown 65532:65532 mist.json mist-api-token audit-hmac.key tokens.json
```

**For local testing without root**, run the container as yourself instead. The
files stay owned by you and nothing needs `sudo`:

```bash
--user "$(id -u):$(id -g)"
```

Both work. The examples below use the second, which is what was verified.

## 3. Run it — lab mode

Pin the image by immutable digest rather than a mutable tag. Pull the image
and capture its digest (RepoDigests is empty until the image is pulled):

```bash
docker pull ghcr.io/mechubsec/rustmistmcp:0.3.2
image=$(docker inspect ghcr.io/mechubsec/rustmistmcp:0.3.2 \
    --format='{{index .RepoDigests 0}}')
```

Then run with the digest:

```bash
mkdir -p mist-labmode-state
docker run -d --name mist-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30044:30030 \
  -v "$PWD/mist.json:/etc/rustmistmcp/mist.json:ro" \
  -v "$PWD/mist-api-token:/etc/rustmistmcp/mist-api-token:ro" \
  -v "$PWD/audit-hmac.key:/var/lib/rustmistmcp/audit-hmac.key:rw" \
  -v "$PWD/tokens.json:/var/lib/rustmistmcp/tokens.json:ro" \
  -v "$PWD/mist-labmode-state:/var/lib/rustmistmcp/state:rw" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30030 \
  --state-file /var/lib/rustmistmcp/state/changeset-state.json \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30044 --allowed-host localhost:30044 \
  --allowed-origin http://console.example.org \
  --lab-mode
```

Configuration and credentials are mounted read-only. A **separate read-write
state directory** is mounted because change-set state must outlive the
container — removing the container without it discards any non-terminal
operations. The published port is bound to **loopback only** (`-p 127.0.0.1:...`)
because `--allowed-host` and `--allowed-origin` are header checks, not a
network boundary; external access needs TLS.

**The origin scheme must match the server's TLS configuration.** These plaintext
examples use `http://` origins because the server runs `--allow-insecure-bind`
with no TLS configured. An HTTPS console origin (`https://...`) requires
`--tls-cert` and `--tls-key` on the listener — browsers block HTTPS→HTTP calls
as active mixed content before Origin validation runs.

Lab mode waives the approval gate and records `approval_waiver=lab-mode` in
the audit trail. **Do not point it at a production org.**

## 4. Run it — two-person mode

Identical but for `--lab-mode`, a different published port, and a separate
state directory so both can run side by side (reuse the `$image` variable from
the previous block):

```bash
mkdir -p mist-twoperson-state
docker run -d --name mist-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30034:30030 \
  -v "$PWD/mist.json:/etc/rustmistmcp/mist.json:ro" \
  -v "$PWD/mist-api-token:/etc/rustmistmcp/mist-api-token:ro" \
  -v "$PWD/audit-hmac.key:/var/lib/rustmistmcp/audit-hmac.key:rw" \
  -v "$PWD/tokens.json:/var/lib/rustmistmcp/tokens.json:ro" \
  -v "$PWD/mist-twoperson-state:/var/lib/rustmistmcp/state:rw" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30030 \
  --state-file /var/lib/rustmistmcp/state/changeset-state.json \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30034 --allowed-host localhost:30034 \
  --allowed-origin http://console.example.org
```

**Note the port asymmetry, because it catches people.** The server always
listens on `30030` *inside* the container; `-p 30034:30030` publishes it as
30034 on the host. But `--allowed-host` and `--allowed-origin` are matched
against the `Host` and `Origin` headers the **client** sends, and the client is
talking to 30034. So those flags carry the *published* port, not the internal
one. Get this wrong and the server starts cleanly and then refuses every request
with `421`.

## 5. Verify

```bash
docker ps --filter name=mist- --format '{{.Names}} {{.Status}}'

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30044/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30034/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
```

**`401` is the success case**: the transport is up and authentication is being
enforced. `000` means nothing is listening — check `docker logs`. A `421` means
the allow-lists do not match the address the client used.

Confirm the mode is what you intended:

```bash
docker logs mist-labmode 2>&1 | grep -i 'lab mode'
```

Confirm the audit configuration is present:

```bash
docker inspect mist-labmode --format '{{join .Args " "}}' | grep audit
```

You should see `--audit-format json --audit-redact ... --audit-hmac-key-file`.
If that prints nothing, you dropped the audit flags — see the warning at the
top of this document.

## 6. Stop

```bash
docker stop mist-labmode mist-twoperson
docker rm mist-labmode mist-twoperson
```

`docker stop` sends SIGTERM and waits, which lets the server finish in-flight
work and flush its state. Avoid `docker kill` for anything holding change-set
state: a process killed mid-write leaves an operation non-terminal, and the next
caller finds the change set blocked.

## Troubleshooting

**`Error: non-loopback bind '0.0.0.0' requires at least one --allowed-origin`**

Binding anything other than loopback demands an explicit origin allow-list. This
is a guard, not an inconvenience: a container published to a host port is
reachable by any browser page that can resolve it, and the origin list is what
stops one driving your Mist orgs. Add `--allowed-origin` for each address a
client will use.

**Server starts but all requests return `421 Misdirected Request`**

The `--allowed-host` and `--allowed-origin` values do not match what the client
is sending. These flags are checked against the **client's** headers, so they
carry the *published* host port (e.g. `30034`), not the internal one (`30030`).
If you published `-p 30034:30030`, use `--allowed-host 127.0.0.1:30034`, not
`:30030`.

**Audit log is missing HMAC keys or redaction**

Since v0.3.1, audit flags live in `ENTRYPOINT` and survive any override — this
should not happen. If you see unhashed `device`, `host`, or `name` fields,
verify the image version and inspect the effective command:

```bash
docker inspect <container> --format '{{join .Args " "}}' | grep audit
```

You should see `--audit-format`, `--audit-redact`, and `--audit-hmac-key-file`
regardless of what flags you passed at `docker run`. If they are missing, you
are running a pre-v0.3.1 image affected by #78 — upgrade to v0.3.1 or later.

**Container exits immediately with no log output**

Check `docker logs` on the stopped container: `docker ps -a --filter name=mist-`.
Startup validation failures print and exit before the transport is up, so the
container is gone by the time you look for it with plain `docker ps`.

**Permission denied reading the config or token files**

The container process is UID 65532 and does not own your files. Either
`chown 65532:65532` them, or run with `--user "$(id -u):$(id -g)"` as shown
above.

**Token mint fails with `error: unknown config file type`**

The token mint command defaults to `devices.json` (from the Junos server), not
`mist.json`. Pass `-f ./mist.json` explicitly.
