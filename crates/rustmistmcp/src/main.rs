//! HPE Juniper Mist MCP server executable.

mod cli;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use cli::{Command, MistCli, Transport};
use mecmcp_auth::TokenStoreFile;
use mecmcp_secret::naming::{ServerNaming, known};
use mecmcp_secret::validate::{CredentialFileRole, CredentialFileSpec, validate_credential_files};
use rmcp::ServiceExt as _;
use rustmistmcp::{
    AuthConfig, KNOWN_TOOLS, MistHandler, install_audit_reopen_handler,
    install_token_reload_handler, serve_http,
};
use rustmistmcp_core::{MistConfig, MistGrant};
use std::path::{Path, PathBuf};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let args = MistCli::parse();

    // Validate the flattened shared CLI
    mecmcp_runtime::cli_validate::validate(&args.shared)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let audit_sink = init_audit(&args)?;

    if let Some(Command::Token { action }) = args.shared.command {
        // Management is deliberately local: it validates against the fixed
        // tool registry and neither loads Mist profile/credential data nor
        // contacts the Mist service.
        return mecmcp_runtime::token_cmd::run_with_grant::<MistGrant>(
            action,
            &[], // No known devices - Mist uses org/site targets
            KNOWN_TOOLS,
            None, // No grant for basic token operations
        )
        .map_err(|error| anyhow::anyhow!("{error}"));
    }

    // Reopen the audit log on SIGHUP (unix only; a no-op install elsewhere),
    // independent of the token store or transport: stdio mode and
    // --allow-no-auth still audit to a file and still need rotation to work,
    // and SIGHUP's default disposition otherwise terminates those
    // deployments outright the moment logrotate signals them.
    if let Some(sink) = audit_sink.clone() {
        install_audit_reopen_handler(sink).context("installing audit log reopen handler")?;
    }

    // Lab mode removes two-person control, so say so where an operator will
    // actually see it. Reading it off flags typed weeks ago is not visibility.
    if args.lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets are approved on creation with no second \
             principal. Records carry approval_waiver=lab-mode. Do not run this against \
             production devices."
        );
    }

    // mecmcp decision D4: the consumer installs the process-global rustls crypto
    // provider, and it must be installed before ANYTHING builds a TLS-capable
    // client. This used to live inside `load_listener_tls`, which only runs when
    // --tls-cert/--tls-key are set — fine while the only TLS consumer was the
    // listener, wrong the moment the outbound Mist client became real. Without
    // it the server died at startup with "failed to construct HTTP client",
    // which the OCI smoke test caught and no unit test could.
    //
    // `install_default` errors if a provider is already set; that is a benign
    // race with anything else in-process, so it is deliberately ignored.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Resolve before the mode pass so a legacy `/etc` store is the file that
    // gets checked, not the canonical path that is not there yet. Stdio never
    // loads that store: the image ENTRYPOINT always passes `--tokens-file`,
    // and `docker run -i <image> --transport stdio` must still start when
    // nothing is mounted at that path.
    let tokens_resolved = listener_tokens(&args)?;
    // `init_audit` already created a missing HMAC key, so the mode pass sees
    // the file it will actually use.
    let credential_file = configured_credential_file(&args.shared.device_mapping);
    validate_startup_credentials(&StartupCredentialFiles {
        config: &args.shared.device_mapping,
        credential_file: credential_file.as_deref(),
        tokens: tokens_resolved
            .as_ref()
            .map(|resolved| resolved.path.as_path()),
        audit_hmac_key: args.shared.audit_hmac_key_file.as_deref(),
        approval_digest_key: args.shared.approval_digest_key_file.as_deref(),
    })
    .context("credential file validation")?;

    // The shared CLI retains the historic `device_mapping` spelling. Here it
    // selects the singleton Mist profile until mecmcp#91 lands.
    let config = MistConfig::from_path(&args.shared.device_mapping)
        .with_context(|| format!("loading {}", args.shared.device_mapping.display()))?;

    // Construct real HTTP client when credential is available
    // Built before the handler because its coordinator takes the recorder, and
    // started eagerly so a misconfiguration stops the server here rather than
    // at the first change.
    let evidence = match args.shared.evidence.into_config() {
        Ok(Some(evidence_config)) => {
            tracing::info!(
                server_id = %evidence_config.server_id,
                run_id = %evidence_config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let transport = std::sync::Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.shared.evidence.ca_file(),
                    provider,
                )
                .map_err(|error| {
                    anyhow::anyhow!("building the SSDF evidence transport: {error}")
                })?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(evidence_config, transport)
                    .map_err(|error| {
                        anyhow::anyhow!("starting the SSDF evidence pipeline: {error}")
                    })?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };

    let approval_digest_key =
        load_approval_digest_key(args.shared.approval_digest_key_file.as_deref())?;

    let handler = MistHandler::from_config_with_lab_mode(
        &config,
        BTreeMap::new(),
        &args.state_file,
        args.lab_mode,
        evidence
            .as_ref()
            .map(mecmcp_audit::EvidenceService::recorder),
        approval_digest_key,
        std::time::Duration::from_secs(args.approval_timeout_secs),
    )
    .context("constructing Mist handler with HTTP client")?;
    tracing::info!(
        "Mist handler constructed with HttpMistClient for endpoint {}",
        config.endpoint
    );

    // Populate the site map before serving. Without this, every site-scoped
    // tool call is refused: `from_config_with_lab_mode` above was handed an
    // empty map, and `MistHandler` treats an unknown site as unauthorized
    // rather than guessing.
    let discovered = rustmistmcp::site_discovery::discover_sites(
        handler.client().as_ref(),
        handler.catalog(),
        handler.origin(),
        handler.allowed_orgs(),
    )
    .await;
    let discovered_count = discovered.sites.len();
    let incomplete_orgs = discovered.incomplete_orgs.len();
    match handler.replace_sites(discovered.sites) {
        Ok(()) => {
            tracing::info!(
                sites = discovered_count,
                incomplete_orgs,
                "discovered Mist org sites at startup"
            );
        }
        Err(error) => {
            tracing::error!(
                %error,
                "discovered site map failed validation at startup; site-scoped tools will be \
                 refused until a refresh succeeds"
            );
        }
    }

    let site_refresh = if args.site_refresh_interval_secs > 0 {
        Some(rustmistmcp::site_discovery::spawn_refresh_loop(
            handler.clone(),
            std::time::Duration::from_secs(args.site_refresh_interval_secs),
        ))
    } else {
        None
    };

    let served = match args.shared.transport {
        Transport::Stdio => serve_stdio(handler).await,
        Transport::StreamableHttp => {
            let auth_config = load_http_token_store(&args)?;
            if let AuthConfig::Authenticated(store) = &auth_config {
                install_token_reload_handler(store.clone())
                    .context("installing token snapshot reload handler")?;
            }
            let tls = load_listener_tls(&args)?;
            let host = args
                .shared
                .host
                .parse::<std::net::IpAddr>()
                .context("invalid --host IP address")?;
            let address = SocketAddr::new(host, args.shared.port);
            refuse_lab_mode_off_loopback(args.lab_mode, &address)?;
            let shutdown = tokio_util::sync::CancellationToken::new();

            // Install signal handlers
            let signal_shutdown = shutdown.clone();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
                let mut sigint =
                    signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
                tokio::spawn(async move {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            tracing::info!("SIGTERM received");
                        }
                        _ = sigint.recv() => {
                            tracing::info!("SIGINT received");
                        }
                    }
                    signal_shutdown.cancel();
                });
            }
            #[cfg(not(unix))]
            {
                tokio::spawn(async move {
                    tokio::signal::ctrl_c().await.ok();
                    tracing::info!("Ctrl+C received");
                    signal_shutdown.cancel();
                });
            }

            let shutdown_timeout = std::time::Duration::from_secs(10);
            serve_http(
                handler,
                address,
                auth_config,
                args.shared.allowed_host,
                args.shared.allowed_origin,
                mecmcp_transport::LimitsConfig::default(),
                false,
                tls,
                args.shared.allow_insecure_bind,
                shutdown,
                shutdown_timeout,
            )
            .await
            .map_err(anyhow::Error::from)
        }
    };

    if let Some(site_refresh) = site_refresh {
        site_refresh.abort();
    }

    // Deliver what is still spooled before leaving, whichever way serving
    // ended. Bound rather than returned directly so the flush runs even when
    // the transport returned an error -- that is exactly when the trail matters.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

/// Pre-provision the audit HMAC key file at `path` if it is absent or empty,
/// mirroring `packaging/lxc/install.sh`'s own key-generation step so every
/// entry point -- LXC install, systemd start, or a container's first run --
/// converges on the same keyed-audit posture instead of only the LXC path
/// doing it (mecmcp#376 / MEC-978). `--audit-redact` still defaults to empty
/// (redaction stays opt-in), so this alone does not turn redaction on; it
/// just means the key is already there the moment an operator flips
/// `--audit-redact ...=hmac` on, instead of failing on that first restart.
///
/// A zero-byte key file is indistinguishable from "never generated" and
/// would make every HMAC output constant, so rewriting it here is a repair,
/// not data loss. A non-empty file is never rotated -- that would silently
/// break verification of every audit record signed under the old key.
fn ensure_audit_hmac_key(path: &std::path::Path) -> Result<()> {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| {
        anyhow::anyhow!("generating audit HMAC key: OS entropy source unavailable: {e}")
    })?;
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating audit HMAC key file {}", path.display()))?;
        use std::io::Write as _;
        file.write_all(hex_key.as_bytes())
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &hex_key)
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }

    Ok(())
}

fn init_audit(args: &MistCli) -> Result<Option<mecmcp_audit::AuditFileSink>> {
    if let Some(key_path) = args.shared.audit_hmac_key_file.as_deref() {
        ensure_audit_hmac_key(key_path).context("pre-provisioning audit HMAC key file")?;
    }

    let redaction = if args.shared.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.shared.audit_redact,
                args.shared.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    // This binary does not build the feature needed to honor this flag, so
    // accepting it and silently continuing without it would contradict the
    // flag's own documented behavior. Refuse startup instead of degrading
    // silently.
    if args.shared.otel_endpoint.is_some() {
        anyhow::bail!(
            "--otel-endpoint requires a build of rustmistmcp with mecmcp-audit's `otel` feature, \
             which this binary does not enable"
        );
    }
    let sink = mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.shared.audit_format),
        audit_log_file: args.shared.audit_log_file.clone(),
        redaction,
        journald: args.shared.audit_journald,
        otel: None,
    })
    .context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("rustmistmcp_tool_duration_seconds");
    Ok(sink)
}

/// Load the approval-digest key file, if configured.
///
/// `None` keeps the change-set coordinator on its default (unkeyed) behavior.
/// Propagating the error on a bad path rather than swallowing it matters
/// here: a deployment that configured this believes the stronger guarantee
/// is active, and starting up anyway without it (silently falling back to
/// the weaker default) would make that belief false.
fn load_approval_digest_key(
    path: Option<&std::path::Path>,
) -> Result<Option<mecmcp_changeset::ApprovalDigestKey>> {
    path.map(|path| {
        mecmcp_changeset::ApprovalDigestKey::load_from_file(path)
            .with_context(|| format!("loading --approval-digest-key-file {}", path.display()))
    })
    .transpose()
}

async fn serve_stdio(handler: MistHandler) -> Result<()> {
    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("starting MCP stdio service")?;
    service
        .waiting()
        .await
        .map(|_| ())
        .context("MCP stdio service exited with error")
}

/// Layout for this server. `known::MIST` is the deployed name (`rustmistmcp`),
/// so these paths stay the ones already on disk.
fn server_naming() -> ServerNaming {
    ServerNaming::derive(known::MIST)
}

/// Canonical token store and the legacy `/etc` location an unmigrated
/// install may still be using.
fn token_store_paths() -> (PathBuf, PathBuf) {
    let naming = server_naming();
    (
        naming.state_dir.join("tokens.json"),
        naming.config_dir.join("tokens.json"),
    )
}

/// Token store the HTTP listener will load.
///
/// Stdio does not consult `--tokens-file`. The container `ENTRYPOINT` bakes
/// that flag in, and a stdio start must not fail because the bearer store is
/// absent.
fn listener_tokens(args: &MistCli) -> Result<Option<mecmcp_auth::ResolvedTokenPath>> {
    match args.shared.transport {
        Transport::Stdio => Ok(None),
        Transport::StreamableHttp => match args.shared.tokens_file.as_deref() {
            Some(path) => Ok(Some(resolve_tokens(path)?)),
            None => Ok(None),
        },
    }
}

/// Credential path named by `mist.json`, when the file parses and names one.
///
/// This only discovers the path. Mode is enforced later, with every other
/// file, by [`validate_startup_credentials`]. A missing or unreadable profile
/// yields `None`; the mode pass still reports the profile itself.
fn configured_credential_file(config_path: &Path) -> Option<PathBuf> {
    let bytes = std::fs::read(config_path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let path = value.get("credential_file")?.as_str()?;
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Files whose mode is checked together, before any of them is loaded.
///
/// A startup that checks one file and exits reports the next bad mode only
/// on the next restart. [`validate_startup_credentials`] asks `mecmcp-secret`
/// to report every offender in this list at once.
struct StartupCredentialFiles<'a> {
    /// `mist.json`. Required. Holds an endpoint, an org allowlist, and either
    /// an environment-variable name or a credential path — not the API token —
    /// so group-read (`0640`) is allowed.
    config: &'a Path,
    /// API token file named by `credential_file`. Absent when `credential_env`
    /// is the source, and absent on a fresh install, so a missing file is not
    /// a failure. A present file with a loose mode is.
    credential_file: Option<&'a Path>,
    /// Bearer-token store this process will load. Required when set.
    tokens: Option<&'a Path>,
    /// Audit HMAC key. Required when set; the caller creates a missing key first.
    audit_hmac_key: Option<&'a Path>,
    /// Approval digest key from `--approval-digest-key-file`. Required when set.
    approval_digest_key: Option<&'a Path>,
}

/// Check every credential-adjacent file in one pass.
///
/// Existing paths are unchanged: the profile path is whatever
/// `--device-mapping` names, the credential path is the one that profile
/// names, and the token path is the one [`resolve_tokens`] already selected,
/// including the legacy `/etc` store when that fallback is in effect.
fn validate_startup_credentials(files: &StartupCredentialFiles<'_>) -> Result<()> {
    let mut specs = Vec::with_capacity(5);
    specs.push(CredentialFileSpec {
        path: files.config,
        role: CredentialFileRole::ConfigNoSecret,
        description: "Mist profile",
        required: true,
    });
    if let Some(path) = files.credential_file {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "Mist API credential file",
            required: false,
        });
    }
    if let Some(path) = files.tokens {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "bearer token store",
            required: true,
        });
    }
    if let Some(path) = files.audit_hmac_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "audit HMAC key",
            required: true,
        });
    }
    if let Some(path) = files.approval_digest_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "approval digest key",
            required: true,
        });
    }

    validate_credential_files(&specs)?;
    Ok(())
}

/// The migration fallback exists so an upgrade that has not yet moved
/// `/etc/rustmistmcp/tokens.json` still starts. It must not apply to an operator's
/// own path: if `--tokens-file /srv/custom.json` is missing — a typo, or a deleted
/// store — falling back to the legacy file would silently reactivate unrelated
/// or revoked credentials. A non-canonical path is loaded directly and fails if
/// absent, which is the honest outcome.
fn resolve_tokens(configured: &std::path::Path) -> Result<mecmcp_auth::ResolvedTokenPath> {
    let (canonical, legacy) = token_store_paths();
    resolve_tokens_with(configured, &canonical, &legacy)
}

/// The rule behind [`resolve_tokens`], with the two well-known paths injected so
/// it can be exercised against real files in a test rather than against absolute
/// paths that never exist there.
fn resolve_tokens_with(
    configured: &std::path::Path,
    canonical: &std::path::Path,
    legacy: &std::path::Path,
) -> Result<mecmcp_auth::ResolvedTokenPath> {
    // Byte-exact, not `Path` equality. `Path` comparison normalizes away trailing
    // separators and `.` components, so `/var/lib/<svc>/tokens.json/` compares
    // EQUAL to the canonical path — while `metadata()` on that spelling returns
    // NotFound when the file is absent, indistinguishable from the plain form.
    // A typo would therefore pass this gate and activate the legacy store, which
    // is exactly the fail-closed behaviour this check exists to provide.
    if configured.as_os_str() != canonical.as_os_str() {
        return Ok(mecmcp_auth::ResolvedTokenPath {
            path: configured.to_path_buf(),
            used_fallback: false,
            fallback_from: None,
        });
    }

    mecmcp_auth::resolve_token_path(configured, legacy).context("resolving token file path")
}

fn load_http_token_store(args: &MistCli) -> Result<AuthConfig> {
    match (&args.shared.tokens_file, args.shared.allow_no_auth) {
        (Some(path), _) => {
            // Issue #42: the configured path is the primary; the legacy /etc
            // location is the fallback, so an upgrade whose tokens have not been
            // moved yet still starts.
            //
            // The migration fallback applies ONLY when the configured path is
            // exactly `/var/lib/rustmistmcp/tokens.json` — the path the shipped
            // unit passes. Any other path is used verbatim and fails if absent,
            // which is the honest outcome for a typo or a deleted custom store.
            let resolved = resolve_tokens(path)
                .with_context(|| format!("resolving token path for {}", path.display()))?;

            if resolved.used_fallback {
                tracing::warn!(
                    primary = %path.display(),
                    fallback = %resolved.path.display(),
                    "tokens.json: configured path not found, reading the legacy /etc location. \
                     Migrate the file to the configured path; it is NOT copied automatically, \
                     and /etc is read-only to the service under ProtectSystem=strict."
                );
            }

            let store = Arc::new(
                TokenStoreFile::<MistGrant>::load(&resolved.path)
                    .with_context(|| format!("loading {}", resolved.path.display()))?,
            );
            tracing::info!(
                path = %resolved.path.display(),
                tokens = store.store().len(),
                "token store loaded"
            );

            // Issue #43: warn about stale secrets alongside the live token file
            warn_about_stale_secrets(&resolved.path);

            Ok(AuthConfig::Authenticated(store))
        }
        (None, true) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts ordinary read/local metadata requests \
                 without authentication on loopback; restricted reads and mutations remain denied"
            );
            Ok(AuthConfig::ExplicitlyUnauthenticated)
        }
        (None, false) => {
            anyhow::bail!(
                "HTTP transport requires either --tokens-file or --allow-no-auth; \
                 refusing to serve unauthenticated without explicit acknowledgement"
            )
        }
    }
}

/// Detect and warn about superseded token files alongside the live one.
///
/// Issue #43: root-owned superseded token files bypass permission checks and
/// accumulate revoked credentials. Warn only — deletion is a production
/// change-window task.
/// Infallible by design: this is advisory. Nothing it can discover — or fail to
/// discover — justifies refusing to start a server whose token store loaded fine.
fn warn_about_stale_secrets(live_path: &std::path::Path) {
    let Some(parent) = live_path.parent() else {
        tracing::debug!(
            path = %live_path.display(),
            "skipping stale-secret scan: token path has no parent directory"
        );
        return;
    };

    // A non-UTF-8 basename is legal on Unix. The token store itself loads fine in
    // that case, so refusing to start because an advisory scan cannot render the
    // name would turn a warning-only feature into an availability failure. Skip
    // the scan and say why.
    let Some(live_file_name) = live_path.file_name().and_then(|n| n.to_str()) else {
        tracing::debug!(
            path = %live_path.display(),
            "skipping stale-secret scan: token filename is not valid UTF-8"
        );
        return;
    };

    let stale = mecmcp_auth::find_stale_secrets(parent, &[live_file_name]);
    if !stale.is_empty() {
        tracing::warn!(
            count = stale.len(),
            directory = %parent.display(),
            "found stale secret files — these may contain revoked credentials and \
             should be deleted after confirming the live file carries all active tokens"
        );
        for item in &stale {
            tracing::warn!(
                path = %item.path.display(),
                reason = ?item.reason,
                "stale secret detected"
            );
        }
    }
}

/// Refuse to start with `--lab-mode` unless the listener binds loopback.
///
/// Lab mode routes every change set through `ChangesetCoordinator::waive_approval`
/// on creation (see `plan_mist_change`): it skips the human-approver gate this
/// server otherwise routes through mecmcp's `approve_change_set`, and does so for
/// every caller that reaches the listener, not merely a single trusted operator.
/// That is the documented single-operator escape hatch (`--lab-mode`'s own help
/// text says "do not run this against production devices"), and it stops being
/// single-operator the moment the listener accepts a connection from anywhere but
/// the machine it runs on. Fail fast at startup instead of letting an operator
/// discover the gate is off only after a non-loopback client used it.
///
/// # Errors
///
/// Returns an error when `lab_mode` is set and `address` is not loopback
/// (`127.0.0.0/8` or `::1`).
fn refuse_lab_mode_off_loopback(lab_mode: bool, address: &SocketAddr) -> Result<()> {
    if lab_mode && !address.ip().is_loopback() {
        anyhow::bail!(
            "--lab-mode waives the human-approver gate for every caller that reaches the \
             listener, so it may only be combined with a loopback bind address \
             (127.0.0.0/8 or ::1); got {}. Bind --host 127.0.0.1 (or ::1), or remove \
             --lab-mode.",
            address.ip()
        );
    }
    Ok(())
}

fn load_listener_tls(args: &MistCli) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let (Some(cert), Some(key)) = (&args.shared.tls_cert, &args.shared.tls_key) else {
        return Ok(None);
    };
    // The process-global provider is installed in `main`; do not install again —
    // `install_default` returns Err when one is already set, and treating that
    // as fatal would break every TLS start.
    let provider = rustls::crypto::ring::default_provider();
    mecmcp_transport::load_tls(cert, key, Arc::new(provider))
        .context("loading listener TLS")
        .map(Some)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_runtime::cli::Transport;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Verify that the (None, false) case — neither --tokens-file nor
    /// --allow-no-auth — is refused at startup rather than silently serving
    /// unauthenticated.
    #[test]
    fn none_false_refuses_to_serve_unauthenticated() {
        let args = MistCli {
            shared: mecmcp_runtime::cli::Cli {
                evidence: mecmcp_runtime::cli::EvidenceArgs::default(),
                transport: Transport::StreamableHttp,
                host: "127.0.0.1".to_owned(),
                port: 8080,
                tokens_file: None,
                allow_no_auth: false,
                allowed_host: vec![],
                allowed_origin: vec![],
                allow_insecure_bind: false,
                tls_cert: None,
                tls_key: None,
                device_mapping: PathBuf::from("/dev/null"),
                audit_format: String::new(),
                audit_redact: String::new(),
                audit_log_file: None,
                audit_hmac_key_file: None,
                audit_journald: false,
                command: None,
                otel_endpoint: None,
                otel_service_name: "mecmcp".to_owned(),
                approval_digest_key_file: None,
            },
            state_file: PathBuf::from("/dev/null/changeset-state.json"),
            approval_timeout_secs: 3600,
            lab_mode: false,
            web_approver: Default::default(),
            site_refresh_interval_secs: 0,
        };

        let result = load_http_token_store(&args);
        assert!(
            result.is_err(),
            "load_http_token_store must refuse (None, false) with an error"
        );
        let error = result
            .expect_err("(None, false) must be refused")
            .to_string();
        assert!(
            error.contains("requires either --tokens-file or --allow-no-auth"),
            "error message should explain the requirement, got: {error}"
        );
    }

    /// Verify that --allow-no-auth explicitly permits unauthenticated serving.
    #[test]
    fn explicit_no_auth_is_permitted() {
        let args = MistCli {
            shared: mecmcp_runtime::cli::Cli {
                evidence: mecmcp_runtime::cli::EvidenceArgs::default(),
                transport: Transport::StreamableHttp,
                host: "127.0.0.1".to_owned(),
                port: 8080,
                tokens_file: None,
                allow_no_auth: true,
                allowed_host: vec![],
                allowed_origin: vec![],
                allow_insecure_bind: false,
                tls_cert: None,
                tls_key: None,
                device_mapping: PathBuf::from("/dev/null"),
                audit_format: String::new(),
                audit_redact: String::new(),
                audit_log_file: None,
                audit_hmac_key_file: None,
                audit_journald: false,
                command: None,
                otel_endpoint: None,
                otel_service_name: "mecmcp".to_owned(),
                approval_digest_key_file: None,
            },
            state_file: PathBuf::from("/dev/null/changeset-state.json"),
            approval_timeout_secs: 3600,
            lab_mode: false,
            web_approver: Default::default(),
            site_refresh_interval_secs: 0,
        };

        let result = load_http_token_store(&args);
        assert!(
            result.is_ok(),
            "load_http_token_store must permit explicit --allow-no-auth"
        );
        assert!(
            matches!(
                result.expect("--allow-no-auth must yield an explicit acknowledgement"),
                AuthConfig::ExplicitlyUnauthenticated
            ),
            "result should be ExplicitlyUnauthenticated"
        );
    }

    /// `known::MIST` keeps the directories already deployed. A rename here would
    /// move live token stores.
    #[test]
    fn derived_token_paths_match_the_deployed_layout() {
        let (canonical, legacy) = token_store_paths();
        assert_eq!(canonical, PathBuf::from("/var/lib/rustmistmcp/tokens.json"));
        assert_eq!(legacy, PathBuf::from("/etc/rustmistmcp/tokens.json"));
    }

    /// The canonical path is absent and the legacy store exists: the fallback
    /// must fire, so an upgrade that has not migrated yet still starts.
    #[test]
    fn canonical_path_falls_back_to_an_existing_legacy_store() {
        let dir = tempfile::tempdir().expect("creating tempdir");
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").expect("writing legacy token file");

        let resolved =
            resolve_tokens_with(&canonical, &canonical, &legacy).expect("resolving token path");
        assert_eq!(
            resolved.path, legacy,
            "the legacy store should have been used"
        );
        assert!(
            resolved.used_fallback,
            "fallback should have been triggered"
        );
    }

    /// The same legacy store exists, but the operator configured a DIFFERENT
    /// path. Falling back here would silently reactivate credentials they did
    /// not ask for — a typo or a deleted store must fail, not resurrect tokens.
    #[test]
    fn a_custom_path_never_falls_back_to_the_legacy_store() {
        let dir = tempfile::tempdir().expect("creating tempdir");
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").expect("writing legacy token file");
        let custom = dir.path().join("operator-chosen.json");

        let resolved =
            resolve_tokens_with(&custom, &canonical, &legacy).expect("resolving token path");
        assert_eq!(
            resolved.path, custom,
            "an operator-supplied path must be used verbatim"
        );
        assert!(
            !resolved.used_fallback,
            "a custom path must never resolve to the legacy /etc store"
        );
    }

    /// A malformed spelling of the canonical path must NOT reach the fallback.
    ///
    /// `Path` equality normalizes away a trailing separator, so
    /// `.../tokens.json/` compares equal to the canonical path; and when the
    /// file is absent `metadata()` returns NotFound for that spelling too,
    /// indistinguishable from the plain form. A typo would therefore activate
    /// the legacy store — the opposite of fail-closed. The comparison is
    /// byte-exact for this reason.
    #[test]
    fn a_trailing_slash_spelling_does_not_reach_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let mut malformed = canonical.clone().into_os_string();
        malformed.push("/");
        let malformed = std::path::PathBuf::from(malformed);

        let resolved = resolve_tokens_with(&malformed, &canonical, &legacy).unwrap();
        assert!(
            !resolved.used_fallback,
            "a trailing-slash spelling must not activate the legacy store"
        );
        assert_eq!(
            resolved.path, malformed,
            "the given path must be used verbatim"
        );
    }

    /// `--lab-mode` on a non-loopback bind address must fail fast with a clear
    /// error, not start a listener that waives the approval gate for every
    /// remote caller.
    #[test]
    fn lab_mode_off_loopback_is_refused() {
        let address: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let error = refuse_lab_mode_off_loopback(true, &address)
            .expect_err("lab mode on a non-loopback address must be refused");
        let message = error.to_string();
        assert!(message.contains("--lab-mode"), "{message}");
        assert!(message.contains("loopback"), "{message}");

        let ipv6_address: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        assert!(
            refuse_lab_mode_off_loopback(true, &ipv6_address).is_err(),
            "a non-loopback IPv6 address must also be refused"
        );
    }

    /// Loopback binds (both IPv4 127.0.0.0/8 and IPv6 ::1) are permitted with
    /// `--lab-mode`.
    #[test]
    fn lab_mode_on_loopback_is_permitted() {
        let ipv4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        refuse_lab_mode_off_loopback(true, &ipv4).expect("IPv4 loopback must be permitted");

        let ipv4_wide: SocketAddr = "127.4.5.6:8080".parse().unwrap();
        refuse_lab_mode_off_loopback(true, &ipv4_wide)
            .expect("the whole 127.0.0.0/8 range must be permitted");

        let ipv6: SocketAddr = "[::1]:8080".parse().unwrap();
        refuse_lab_mode_off_loopback(true, &ipv6).expect("IPv6 loopback must be permitted");
    }

    /// Without `--lab-mode`, the bind address is not this check's business at
    /// all -- a non-loopback bind is a separate concern the shared CLI
    /// validator and `--allow-insecure-bind` already gate.
    #[test]
    fn non_lab_mode_ignores_bind_address() {
        let address: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        refuse_lab_mode_off_loopback(false, &address)
            .expect("without --lab-mode, any bind address is this check's no-op");
    }

    /// No `--approval-digest-key-file` keeps the coordinator unkeyed, same as
    /// today.
    #[test]
    fn no_approval_digest_key_file_is_fine() {
        assert!(
            load_approval_digest_key(None)
                .expect("no path is not an error")
                .is_none()
        );
    }

    /// A valid key file is loaded, not silently dropped.
    #[test]
    fn a_valid_approval_digest_key_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"a-sufficiently-long-test-key-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let key = load_approval_digest_key(Some(&path))
            .expect("a valid key file must load")
            .expect("Some(path) must produce Some(key)");
        assert_eq!(&*key, b"a-sufficiently-long-test-key-value");
    }

    /// A key file that fails `mecmcp-changeset`'s checks (here: too short)
    /// must fail startup, not fall back to the weaker default behavior.
    /// Silently ignoring an invalid key would leave a deployment on weaker
    /// behavior than it configured, believing otherwise.
    #[test]
    fn a_too_short_approval_digest_key_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"short").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = load_approval_digest_key(Some(&path))
            .expect_err("a too-short key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }

    /// A missing key file must fail startup rather than silently starting
    /// unkeyed -- the operator asked for a keyed digest and typo'd the path.
    #[test]
    fn a_missing_approval_digest_key_file_fails_closed() {
        let error = load_approval_digest_key(Some(std::path::Path::new(
            "/nonexistent/does-not-exist/key",
        )))
        .expect_err("a missing key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }

    /// A flag this binary cannot honor must refuse startup rather than
    /// silently dropping the behavior it promises.
    #[test]
    fn otel_endpoint_set_refuses_to_start() {
        let mut args = base_cli_for_otel_test();
        args.shared.otel_endpoint = Some("http://127.0.0.1:4318".to_owned());

        let error = init_audit(&args).expect_err("--otel-endpoint must be refused by this binary");
        assert!(error.to_string().contains("--otel-endpoint"), "{error}");
    }

    /// No `--otel-endpoint` keeps today's behaviour: audit initializes with
    /// `otel: None`.
    #[test]
    fn no_otel_endpoint_starts_normally() {
        let args = base_cli_for_otel_test();
        init_audit(&args).expect("no --otel-endpoint must not be refused");
    }

    fn base_cli_for_otel_test() -> MistCli {
        MistCli {
            shared: mecmcp_runtime::cli::Cli {
                evidence: mecmcp_runtime::cli::EvidenceArgs::default(),
                transport: Transport::StreamableHttp,
                host: "127.0.0.1".to_owned(),
                port: 8080,
                tokens_file: None,
                allow_no_auth: true,
                allowed_host: vec![],
                allowed_origin: vec![],
                allow_insecure_bind: false,
                tls_cert: None,
                tls_key: None,
                device_mapping: PathBuf::from("/dev/null"),
                audit_format: String::new(),
                audit_redact: String::new(),
                audit_log_file: None,
                audit_hmac_key_file: None,
                audit_journald: false,
                command: None,
                otel_endpoint: None,
                otel_service_name: "mecmcp".to_owned(),
                approval_digest_key_file: None,
            },
            state_file: PathBuf::from("/dev/null/changeset-state.json"),
            approval_timeout_secs: 3600,
            lab_mode: false,
            web_approver: Default::default(),
            site_refresh_interval_secs: 0,
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod startup_credential_tests {
    use super::{StartupCredentialFiles, validate_startup_credentials};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn write_file(dir: &std::path::Path, name: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// Two loose modes must come back together. The failure this guards is a
    /// startup that names the first file, exits, and only names the second
    /// after that restart.
    #[test]
    fn one_pass_reports_every_bad_mode() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(dir.path(), "mist.json", 0o644);
        let tokens = write_file(dir.path(), "tokens.json", 0o640);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            config: &config,
            credential_file: None,
            tokens: Some(&tokens),
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("both files are looser than their role allows");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("mist.json"), "{message}");
        assert!(message.contains("tokens.json"), "{message}");
        assert!(message.contains("0644"), "{message}");
        assert!(message.contains("0640"), "{message}");
    }

    /// `0600` is inside the `0640` ceiling for a no-secret profile, and a
    /// `0600` token store is the secret role. Both must pass together.
    #[test]
    fn acceptable_modes_pass_in_one_pass() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(dir.path(), "mist.json", 0o640);
        let tokens = write_file(dir.path(), "tokens.json", 0o600);
        let credential = write_file(dir.path(), "mist-api-token", 0o600);

        validate_startup_credentials(&StartupCredentialFiles {
            config: &config,
            credential_file: Some(&credential),
            tokens: Some(&tokens),
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect("0640 profile, 0600 credential, and 0600 tokens are the packaged modes");
    }

    /// A locked-down profile (`0600`) is stricter than `0640` and must still
    /// start. A missing optional credential file is not a failure.
    #[test]
    fn owner_only_config_and_missing_optional_file_pass() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(dir.path(), "mist.json", 0o600);
        let missing = dir.path().join("mist-api-token");

        validate_startup_credentials(&StartupCredentialFiles {
            config: &config,
            credential_file: Some(&missing),
            tokens: None,
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect("0600 profile and an absent optional credential file must pass");
    }

    /// The credential file holds the API token, so group-read is a failure
    /// even when the profile next to it is an acceptable `0640`.
    #[test]
    fn loose_credential_file_is_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(dir.path(), "mist.json", 0o640);
        let credential = write_file(dir.path(), "mist-api-token", 0o640);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            config: &config,
            credential_file: Some(&credential),
            tokens: None,
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("0640 is too loose for the API credential");

        let message = error.to_string();
        assert!(message.contains("mist-api-token"), "{message}");
        assert!(message.contains("0600"), "{message}");
        assert!(
            !message.contains("mist.json"),
            "an acceptable profile must not be named, got {message}"
        );
    }
}
