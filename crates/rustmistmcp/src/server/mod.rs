//! Curated Mist MCP handler: read tools plus change-set-gated WAN edge mutations.

mod change_set;
mod similarity;
mod wan;
mod wan_write;

use std::{collections::BTreeMap, sync::Arc};

use mecmcp_auth::CallerCtx;
use mecmcp_server::{
    OutputRedaction, ResultFormat, ResultLimits, audit_scope, authorize_call,
    caller_from_extensions, filter_tools_for_scope, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerConfig,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rustmistmcp_core::{
    BlockedMistClient, BudgetStatus, CallPriority, Catalog, MAX_ENCODED_CURSOR_BYTES, MistClient,
    MistError, MistGrant, MistRequest, MistResponseBody, MistTarget,
    catalog::{MistCapability, MistOperation, TargetSelector},
    validate_mist_endpoint,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use url::Url;

/// Exact MCP tool registry used for token validation and drift tests.
pub const KNOWN_TOOLS: &[&str] = &[
    "apply_mist_change_set",
    "approve_mist_change_set",
    "get_mist_change_set",
    "get_mist_device",
    "get_mist_device_stats",
    "get_mist_insight",
    "get_mist_operation_schema",
    "get_mist_org",
    "get_mist_rrm",
    "get_mist_self",
    "get_mist_site",
    "get_mist_sle",
    "get_mist_sle_impact",
    "get_mist_wan_config",
    "get_mist_wan_edge_stats",
    "invoke_mist_privileged_read",
    "invoke_mist_read",
    "list_mist_alarm_definitions",
    "list_mist_applications",
    "list_mist_orgs",
    "list_mist_rogues",
    "list_mist_sites",
    "list_mist_sle_metrics",
    "list_mist_upgrades",
    "list_mist_wan_config",
    "list_mist_wan_edges",
    "list_mist_wlans",
    "plan_mist_change",
    "search_mist_alarms",
    "search_mist_audit_logs",
    "search_mist_bgp_peers",
    "search_mist_clients",
    "search_mist_events",
    "search_mist_inventory",
    "search_mist_operations",
    "search_mist_peer_paths",
    "search_mist_service_path_events",
    "search_mist_tunnels",
    "troubleshoot_mist",
];

/// Privileged reads excluded from wildcard tool scope.
pub const RESTRICTED_TOOLS: &[&str] = &[
    "apply_mist_change_set",
    "approve_mist_change_set",
    "get_mist_change_set",
    "get_mist_device",
    "get_mist_self",
    "get_mist_wan_config",
    "invoke_mist_privileged_read",
    "list_mist_wan_config",
    "list_mist_wlans",
    "plan_mist_change",
    "search_mist_audit_logs",
];

const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

fn audited_tool_result<T, E>(
    audit: &mut mecmcp_audit::AuditScope,
    result: Result<T, E>,
) -> CallToolResult
where
    T: Serialize,
    E: std::fmt::Display,
{
    let domain_error = result.as_ref().err().map(ToString::to_string);
    let output = tool_result(
        result,
        ResultFormat::PrettyJson,
        RESULT_LIMITS,
        OutputRedaction::Apply,
    );
    if output.is_error == Some(true) {
        audit.fail(domain_error.unwrap_or_else(|| {
            "successful domain result failed bounded MCP result conversion".to_owned()
        }));
    } else {
        audit.succeed();
    }
    output
}

type PathValues = BTreeMap<String, String>;
type QueryValues = BTreeMap<String, serde_json::Value>;
type NamedMaps = (PathValues, QueryValues);

struct CatalogRead {
    tool: &'static str,
    operation_id: String,
    path: PathValues,
    query: QueryValues,
    cursor: Option<rustmistmcp_core::MistCursor>,
    capability: MistCapability,
    /// Whether the response body should be redacted before it reaches this
    /// call's [`CallToolResult`].
    ///
    /// `true` for every tool-facing read. `false` only for the handful of
    /// internal reads a write tool issues purely to compare against, or
    /// feed into, its own request body (drift-check fingerprinting,
    /// pre-write verification, the `plan_mist_change` before-state read) --
    /// those results are never handed to the model as-is, and redacting
    /// them would corrupt the comparison or splice `[REDACTED]` into a
    /// device write. Callers that reuse the raw value in a model-facing
    /// response (`plan_mist_change`, `get_mist_change_set`) redact their own
    /// copy of it separately before returning.
    redact_output: bool,
}

/// Failure to construct the immutable Mist handler.
#[derive(Debug, thiserror::Error)]
pub enum MistServerError {
    /// The configured endpoint is not an HTTPS origin.
    #[error("invalid Mist handler endpoint")]
    InvalidEndpoint,
    /// An allowlisted organization is not a canonical UUID.
    #[error("invalid Mist organization allowlist")]
    InvalidOrganization,
    /// The embedded catalog failed its integrity checks.
    #[error("invalid embedded Mist catalog: {0}")]
    Catalog(#[from] rustmistmcp_core::catalog::CatalogError),
    /// Failed to load credential from file.
    #[error("credential load failed: {0}")]
    CredentialLoad(String),
    /// Failed to construct HTTP client.
    #[error("HTTP client construction failed: {0}")]
    ClientConstruction(String),
    /// Failed to load change-set lifecycle state.
    #[error("change-set state load failed: {0}")]
    ChangeSetState(String),
}

/// Validate a candidate site map against the bounds the handler enforces:
/// every site ID and its recorded org ID must be canonical UUIDs, the org
/// must be in the configured allowlist, and the map must not exceed the
/// tracked-site ceiling.
///
/// Shared by both constructors and by [`MistHandler::replace_sites`], so a
/// discovery refresh can never install a map the constructor itself would
/// have rejected.
fn validate_sites(
    sites: &BTreeMap<String, String>,
    allowed_orgs: &[String],
) -> Result<(), MistServerError> {
    if sites.len() > 4096
        || sites.iter().any(|(site_id, org_id)| {
            MistTarget::site(site_id).is_err()
                || MistTarget::org(org_id).is_err()
                || !allowed_orgs.iter().any(|allowed| allowed == org_id)
        })
    {
        return Err(MistServerError::InvalidOrganization);
    }
    Ok(())
}

/// Mist MCP handler with catalogued reads and change-set-gated writes.
///
/// Serves read-only Mist tools and mutating tools gated through the
/// plan → approve → apply → verify change-set lifecycle. Write tools do not
/// exist yet, but the coordinator is mounted to prepare for them.
#[derive(Clone)]
pub struct MistHandler {
    #[allow(dead_code)]
    origin: Url,
    #[allow(dead_code)]
    allowed_orgs: Arc<[String]>,
    /// Site inventory discovered at startup and refreshed periodically by
    /// `crate::site_discovery`, keyed by site UUID.
    ///
    /// `RwLock` rather than an atomic-swap crate: a refresh happens roughly
    /// once every few minutes, every read is synchronous and never held
    /// across an `.await`, and this avoids a new dependency for that.
    sites: Arc<std::sync::RwLock<BTreeMap<String, String>>>,
    #[allow(dead_code)]
    catalog: Arc<Catalog>,
    client: Arc<dyn MistClient>,
    /// Change-set lifecycle state for gated writes.
    #[allow(dead_code)]
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
    /// SSDF evidence recorder, when the pipeline is configured.
    ///
    /// Held here rather than reached through the coordinator, because mecmcp
    /// emits the four records from its *lifecycle* APIs -- `create_change_set`,
    /// `approve_change_set`, `commit_operation` -- and this server only drives
    /// `approve_mist_change_set` through the coordinator's `approve_change_set`
    /// (MEC-408); planning and apply still go through `insert_change_set` /
    /// `update_change_set` directly. Attaching a recorder to the coordinator
    /// alone produces nothing at those call sites, so the emission points are
    /// ours to place.
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    /// Whether lab mode is enabled (auto-waive on creation).
    lab_mode: bool,
    tool_router: ToolRouter<Self>,
}

/// Default change-set limits for this consumer.
///
/// A Mist change set holds one action over one object, so the per-set ceilings
/// are deliberately small; the store ceiling is what bounds a runaway client.
fn change_set_limits() -> mecmcp_changeset::OperationLimits {
    mecmcp_changeset::OperationLimits {
        max_operations: 64,
        max_change_sets: 64,
        max_actions_per_set: 1,
        max_change_set_bytes: 256 * 1024,
        max_state_bytes: 4 * 1024 * 1024,
        max_targets_per_set: 1,
        max_preview_bytes: 128 * 1024,
    }
}

/// Approval timeout used where no CLI value is available (in-memory test and
/// example constructors). Production always threads the parsed
/// `--approval-timeout-secs` value through instead.
const DEFAULT_APPROVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// Load the coordinator for a handler.
///
/// `None` keeps state in memory, which is what tests want. Production passes
/// `/var/lib/rustmistmcp/changeset-state.json`, the path packaging reserves.
fn load_coordinator(
    path: Option<&std::path::Path>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    approval_digest_key: Option<mecmcp_changeset::ApprovalDigestKey>,
    approval_timeout: std::time::Duration,
) -> Result<Arc<mecmcp_changeset::ChangesetCoordinator>, MistServerError> {
    // `load_with_key` verifies any on-disk v6 approval digest against the key
    // and stores it on the returned coordinator for future signs; it must not
    // also be passed to `with_approval_digest_key` afterwards, or the two
    // copies could drift (see mecmcp_runtime::cli::Cli::approval_digest_key_file).
    let mut coordinator = mecmcp_changeset::ChangesetCoordinator::load_with_key(
        path,
        change_set_limits(),
        approval_timeout,
        lab_mode,
        approval_digest_key,
    )
    .map_err(|error| MistServerError::ChangeSetState(error.to_string()))?;
    if let Some(recorder) = evidence {
        coordinator = coordinator.with_evidence(recorder);
    }
    Ok(Arc::new(coordinator))
}

impl MistHandler {
    /// Construct the no-network default handler used when no credential is available.
    ///
    /// No credential is read and no socket is opened.
    pub fn blocked(
        endpoint: &str,
        allowed_orgs: Vec<String>,
        sites: BTreeMap<String, String>,
    ) -> Result<Self, MistServerError> {
        Self::with_client(endpoint, allowed_orgs, sites, Arc::new(BlockedMistClient))
    }
    /// The transport this handler will actually use.
    ///
    /// Exposed so a test can assert which client the *production* constructor
    /// built. A test that constructs the handler itself cannot see the wiring
    /// at all — which is how `from_config` shipped returning the stub.
    #[must_use]
    pub fn client(&self) -> &Arc<dyn MistClient> {
        &self.client
    }

    /// The catalog this handler validates requests and responses against.
    ///
    /// Exposed so startup and periodic site discovery (`crate::site_discovery`)
    /// can validate and issue `listOrgSites` requests through the same
    /// catalog the handler dispatches with, rather than loading a second copy.
    #[must_use]
    pub fn catalog(&self) -> &Arc<Catalog> {
        &self.catalog
    }

    /// The validated Mist API origin this handler was constructed against.
    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.origin
    }

    /// The configured organization allowlist.
    #[must_use]
    pub fn allowed_orgs(&self) -> &Arc<[String]> {
        &self.allowed_orgs
    }

    /// Atomically replace the discovered site map.
    ///
    /// Used by the periodic site-discovery refresh (`crate::site_discovery`)
    /// so newly added or removed sites are picked up without a restart.
    /// Re-validated exactly as the constructors validate their initial
    /// `sites` argument, so a discovered map naming an org outside the
    /// allowlist, or a malformed ID, never reaches request dispatch.
    ///
    /// # Errors
    /// Returns an error, leaving the previous map in place, when `sites`
    /// fails the bounds the constructors enforce.
    pub fn replace_sites(&self, sites: BTreeMap<String, String>) -> Result<(), MistServerError> {
        validate_sites(&sites, &self.allowed_orgs)?;
        *self.sites.write().expect("mist site map lock poisoned") = sites;
        Ok(())
    }

    /// Snapshot the current site map.
    ///
    /// Used by `crate::site_discovery`'s refresh loop to carry forward the
    /// sites of an org whose discovery pass failed or was truncated this
    /// round, so a transient error never wipes out sites already known; also
    /// used by tests to observe that a background refresh landed.
    pub(crate) fn sites_snapshot(&self) -> BTreeMap<String, String> {
        self.sites
            .read()
            .expect("mist site map lock poisoned")
            .clone()
    }

    /// Construct a production handler with real HTTPS client.
    ///
    /// Loads the credential from the config's credential_file and constructs
    /// an HttpMistClient with mecmcp-http.
    ///
    /// # Errors
    ///
    /// Returns errors for invalid config, credential load failure, or client
    /// construction failure.
    pub fn from_config(
        config: &rustmistmcp_core::MistConfig,
        sites: BTreeMap<String, String>,
        state_path: &std::path::Path,
    ) -> Result<Self, MistServerError> {
        Self::from_config_with_lab_mode(
            config,
            sites,
            state_path,
            false,
            None,
            None,
            DEFAULT_APPROVAL_TIMEOUT,
        )
    }

    /// Construct a production handler with optional lab mode.
    ///
    /// When `lab_mode` is true, change sets are waived on creation with no
    /// second-principal approval required.
    ///
    /// # Errors
    ///
    /// Returns errors for invalid config, credential load failure, or client
    /// construction failure.
    pub fn from_config_with_lab_mode(
        config: &rustmistmcp_core::MistConfig,
        sites: BTreeMap<String, String>,
        state_path: &std::path::Path,
        lab_mode: bool,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
        approval_digest_key: Option<mecmcp_changeset::ApprovalDigestKey>,
        approval_timeout: std::time::Duration,
    ) -> Result<Self, MistServerError> {
        // Load credential using mecmcp-secret (enforces mode 0600)
        let credential = mecmcp_secret::load_from_file(
            &config.credential_file,
            mecmcp_secret::SecretLimits::default(),
        )
        .map_err(|error| MistServerError::CredentialLoad(error.to_string()))?;

        // Build HttpMistClient
        let catalog = Arc::new(rustmistmcp_core::Catalog::embedded()?);
        let http_client = rustmistmcp_core::HttpMistClient::new(
            &config.endpoint,
            credential.expose().to_owned(),
            catalog.clone(),
            rustmistmcp_core::HttpMistClientConfig::default(),
        )
        .map_err(|error| MistServerError::ClientConstruction(error.to_string()))?;

        // Load change-set coordinator at the configured state path (the
        // `--state-file` CLI flag; production's default lives there too).
        let coordinator = load_coordinator(
            Some(state_path),
            lab_mode,
            evidence.clone(),
            approval_digest_key,
            approval_timeout,
        )?;

        let origin = validate_mist_endpoint(&config.endpoint)
            .map_err(|_| MistServerError::InvalidEndpoint)?;
        let allowed_orgs = &config.allowed_orgs;
        if allowed_orgs.is_empty()
            || allowed_orgs.len() > 256
            || allowed_orgs
                .iter()
                .any(|org_id| MistTarget::org(org_id).is_err())
            || allowed_orgs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != allowed_orgs.len()
        {
            return Err(MistServerError::InvalidOrganization);
        }
        validate_sites(&sites, allowed_orgs)?;
        Ok(Self {
            origin,
            allowed_orgs: allowed_orgs.clone().into(),
            sites: Arc::new(std::sync::RwLock::new(sites)),
            catalog,
            client: Arc::new(http_client),
            coordinator,
            evidence,
            lab_mode,
            tool_router: Self::mist_tool_router(),
        })
    }

    /// Construct a handler around an injected Mist client.
    pub fn with_client(
        endpoint: &str,
        allowed_orgs: Vec<String>,
        sites: BTreeMap<String, String>,
        client: Arc<dyn MistClient>,
    ) -> Result<Self, MistServerError> {
        Self::with_client_options(endpoint, allowed_orgs, sites, client, None, false)
    }

    /// Same as [`Self::with_client`], but lets a caller pick the change-set
    /// state file and enable lab mode.
    ///
    /// Exists so tests can exercise the `--lab-mode` waive path and prove the
    /// resulting record survives a save/reload cycle. `state_path` of `None`
    /// keeps state in memory, which is what most tests want.
    pub fn with_client_options(
        endpoint: &str,
        allowed_orgs: Vec<String>,
        sites: BTreeMap<String, String>,
        client: Arc<dyn MistClient>,
        state_path: Option<&std::path::Path>,
        lab_mode: bool,
    ) -> Result<Self, MistServerError> {
        let origin =
            validate_mist_endpoint(endpoint).map_err(|_| MistServerError::InvalidEndpoint)?;
        if allowed_orgs.is_empty()
            || allowed_orgs.len() > 256
            || allowed_orgs
                .iter()
                .any(|org_id| MistTarget::org(org_id).is_err())
            || allowed_orgs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != allowed_orgs.len()
        {
            return Err(MistServerError::InvalidOrganization);
        }
        validate_sites(&sites, &allowed_orgs)?;
        Ok(Self {
            origin,
            allowed_orgs: allowed_orgs.into(),
            sites: Arc::new(std::sync::RwLock::new(sites)),
            catalog: Arc::new(Catalog::embedded()?),
            client,
            coordinator: load_coordinator(
                state_path,
                lab_mode,
                None,
                None,
                DEFAULT_APPROVAL_TIMEOUT,
            )?,
            evidence: None,
            lab_mode,
            tool_router: Self::mist_tool_router(),
        })
    }

    /// Same as [`Self::with_client_options`], but with an evidence recorder
    /// attached to both the coordinator and the handler, matching how
    /// `from_config_with_lab_mode` wires production. Test-only: lets a test
    /// inspect the evidence chain a tool call produces.
    #[cfg(test)]
    fn with_client_and_evidence(
        endpoint: &str,
        allowed_orgs: Vec<String>,
        sites: BTreeMap<String, String>,
        client: Arc<dyn MistClient>,
        evidence: Arc<mecmcp_audit::recorder::EvidenceRecorder>,
    ) -> Result<Self, MistServerError> {
        let origin =
            validate_mist_endpoint(endpoint).map_err(|_| MistServerError::InvalidEndpoint)?;
        Ok(Self {
            origin,
            allowed_orgs: allowed_orgs.into(),
            sites: Arc::new(std::sync::RwLock::new(sites)),
            catalog: Arc::new(Catalog::embedded()?),
            client,
            coordinator: load_coordinator(
                None,
                false,
                Some(evidence.clone()),
                None,
                DEFAULT_APPROVAL_TIMEOUT,
            )?,
            evidence: Some(evidence),
            lab_mode: false,
            tool_router: Self::mist_tool_router(),
        })
    }

    /// Whether `target` falls outside the configured org allowlist.
    ///
    /// This is the single allowlist decision for a resolved target, shared
    /// by every caller that needs to check one.
    fn target_allowlist_error(&self, target: Option<&MistTarget>) -> Option<String> {
        let target = target?;
        if target.to_string().starts_with("org/") {
            if !self.allowed_orgs.iter().any(|org| org == target.id()) {
                Some(format!(
                    "organization {} is not in the configured allowlist",
                    target.id()
                ))
            } else {
                None
            }
        } else if target.to_string().starts_with("site/") {
            match self
                .sites
                .read()
                .expect("mist site map lock poisoned")
                .get(target.id())
            {
                None => Some(format!(
                    "site {} is not known (requires org_id for site queries, or the site's parent org in the allowlist)",
                    target.id()
                )),
                Some(org_id) if !self.allowed_orgs.iter().any(|org| org == org_id) => {
                    Some(format!(
                        "site {}'s parent organization {} is not in the configured allowlist",
                        target.id(),
                        org_id
                    ))
                }
                Some(_) => None,
            }
        } else {
            Some("the target is neither an organization nor a site".to_owned())
        }
    }

    async fn dispatch_catalogued_read(
        &self,
        read: CatalogRead,
        extensions: &rmcp::model::Extensions,
    ) -> CallToolResult {
        let CatalogRead {
            tool,
            operation_id,
            path,
            query,
            cursor,
            capability: required_capability,
            redact_output,
        } = read;
        let caller = caller_from_extensions::<MistGrant>(extensions);
        let operation = match self.catalog.operation(&operation_id) {
            Some(operation) => operation,
            None => {
                let mut audit = audit_scope(caller, tool, "read", Vec::new());

                // Find similar operation IDs to suggest
                let suggestions = similarity::find_similar_operations(&self.catalog, &operation_id);

                let mut error_msg = format!(
                    "operation {} is not in the catalog (pinned Mist OpenAPI snapshot: revision {})",
                    operation_id,
                    &self.catalog.source.revision[..8.min(self.catalog.source.revision.len())]
                );

                if !suggestions.is_empty() {
                    error_msg.push_str(". Did you mean:");
                    for (suggested_id, _, capability) in suggestions {
                        error_msg.push_str(&format!("\n  - {}", suggested_id));
                        // Check if the suggested operation requires a different dispatcher
                        if capability != required_capability {
                            let dispatcher_name = match capability {
                                rustmistmcp_core::catalog::MistCapability::OrdinaryRead => {
                                    "invoke_mist_read"
                                }
                                rustmistmcp_core::catalog::MistCapability::PrivilegedRead => {
                                    "invoke_mist_privileged_read"
                                }
                                _ => "(no read dispatcher available for this operation)",
                            };
                            error_msg.push_str(&format!(" (use {} to invoke it)", dispatcher_name));
                        }
                    }
                }

                let error = MistCallError::UnknownOperation(error_msg);
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(error),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                );
            }
        };
        let target = match target_for(operation.target_selectors.as_slice(), &path) {
            Ok(target) => target,
            Err(error) => {
                let mut audit = audit_scope(caller, tool, "read", Vec::new());
                audit.deny("target");
                return tool_result::<ReadEnvelope, _>(
                    Err(error),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                );
            }
        };
        let targets = target
            .as_ref()
            .map(|target| vec![target.subject()])
            .unwrap_or_default();
        let mut audit = audit_scope(caller, tool, "read", targets);
        audit.meta("operation_id", operation_id.clone());

        if operation.method != "GET" || operation.capability != required_capability {
            let dispatcher_name = match operation.capability {
                MistCapability::OrdinaryRead => "invoke_mist_read",
                MistCapability::PrivilegedRead => "invoke_mist_privileged_read",
                _ => "(no read dispatcher available for this operation)",
            };
            let error = MistCallError::WrongCapability(format!(
                "operation {} exists but is classified as {:?} (method {}); use {} to invoke it",
                operation_id, operation.capability, operation.method, dispatcher_name
            ));
            audit.deny("capability");
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        if caller.is_none() && operation.capability == MistCapability::PrivilegedRead {
            let error = MistCallError::Authorization(
                "privileged Mist reads require authenticated caller context".to_owned(),
            );
            audit.deny("caller");
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        if let Err(error) = authorize_call(
            caller,
            tool,
            target.as_ref().map(|target| target.subject()).as_deref(),
            RESTRICTED_TOOLS,
        ) {
            audit.deny("scope");
            return tool_result::<ReadEnvelope, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        if let Err(error) =
            authorize_grant(caller, &operation_id, operation.capability, target.as_ref())
        {
            audit.deny("grant");
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        if let Some(reason) = self.target_allowlist_error(target.as_ref()) {
            let error = MistCallError::OrganizationNotConfigured(reason);
            audit.deny("profile");
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        if let Err(error) = validate_page_limit(&query) {
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }

        let request = MistRequest {
            operation_id,
            path,
            query,
            json: None,
            cursor,
        };
        let request = match request.validate(&self.catalog, &self.origin) {
            Ok(request) => request,
            Err(error) => {
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::Mist(error)),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                );
            }
        };
        let expected_operation_id = request.operation_id.clone();
        let request_path = request.path.clone();
        let request_query = request.query.clone();
        let priority = call_priority_for(caller);
        let response = match self.client.execute_as(request, priority).await {
            Ok(response) => response,
            Err(error) => {
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::Mist(error)),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                );
            }
        };
        let budget_remaining = self.client.budget_status();
        if response.operation_id != expected_operation_id {
            let error = MistError::InvalidResponse {
                operation_id: expected_operation_id,
                reason: "response operation does not match request operation".to_owned(),
            };
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(MistCallError::Mist(error)),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        let mut response = match response.validate(&self.catalog, &self.origin) {
            Ok(response) => response,
            Err(error) => {
                audit.fail(&error);
                return tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::Mist(error)),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                );
            }
        };
        if !(200..300).contains(&response.status) {
            let error = if response.status == 429 {
                MistError::RateLimited {
                    retry_after_secs: None,
                }
            } else if response.status == 410 {
                MistError::EndpointRetired {
                    operation_id: response.operation_id.clone(),
                }
            } else {
                MistError::Service(format!("Mist API returned HTTP {}", response.status))
            };
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(MistCallError::Mist(error)),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        if let Some(cursor) = response.cursor.take() {
            response.cursor =
                match cursor.with_request_context(request_path, request_query, target.clone()) {
                    Ok(cursor) => Some(cursor),
                    Err(error) => {
                        audit.fail(&error);
                        return tool_result::<ReadEnvelope, _>(
                            Err(MistCallError::Mist(error)),
                            ResultFormat::PrettyJson,
                            RESULT_LIMITS,
                            OutputRedaction::Apply,
                        );
                    }
                };
        }
        let envelope =
            ReadEnvelope::from_response(response, target.as_ref(), budget_remaining, redact_output);
        audited_tool_result(&mut audit, Ok::<_, MistCallError>(envelope))
    }

    async fn dispatch_named<T: Serialize>(
        &self,
        tool: &'static str,
        operation_id: &'static str,
        args: T,
        path_names: &[&str],
        capability: MistCapability,
        extensions: &rmcp::model::Extensions,
    ) -> CallToolResult {
        let (path, query) = match named_maps(args, path_names) {
            Ok(values) => values,
            Err(error) => {
                return tool_result::<ReadEnvelope, _>(
                    Err(error),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                );
            }
        };
        self.dispatch_catalogued_read(
            CatalogRead {
                tool,
                operation_id: operation_id.to_owned(),
                path,
                query,
                cursor: None,
                capability,
                redact_output: true,
            },
            extensions,
        )
        .await
    }

    async fn invoke_dispatcher(
        &self,
        tool: &'static str,
        args: InvokeReadArgs,
        capability: MistCapability,
        extensions: &rmcp::model::Extensions,
    ) -> CallToolResult {
        if args.cursor.is_some() && (args.path.is_some() || args.query.is_some()) {
            let error = MistCallError::Mist(MistError::InvalidCursor(
                "cursor cannot be combined with path or query".to_owned(),
            ));
            let mut audit = audit_scope(
                caller_from_extensions::<MistGrant>(extensions),
                tool,
                "read",
                Vec::new(),
            );
            audit.fail(&error);
            return tool_result::<ReadEnvelope, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }
        let (path, query, cursor) = match args.cursor {
            Some(encoded) => {
                let malformed = encoded.is_empty()
                    || encoded.len() > MAX_ENCODED_CURSOR_BYTES
                    || encoded.len() % 2 != 0
                    || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit());
                let decoded = if malformed {
                    None
                } else {
                    hex::decode(encoded)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                };
                let Some(cursor): Option<rustmistmcp_core::MistCursor> = decoded else {
                    let error = MistCallError::Mist(MistError::InvalidCursor(
                        "opaque cursor is malformed".to_owned(),
                    ));
                    let mut audit = audit_scope(
                        caller_from_extensions::<MistGrant>(extensions),
                        tool,
                        "read",
                        Vec::new(),
                    );
                    audit.fail(&error);
                    return tool_result::<ReadEnvelope, _>(
                        Err(error),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    );
                };
                let Some((path, query, _stored_target)) = cursor.request_context() else {
                    let error = MistCallError::Mist(MistError::InvalidCursor(
                        "opaque cursor has no request context".to_owned(),
                    ));
                    let mut audit = audit_scope(
                        caller_from_extensions::<MistGrant>(extensions),
                        tool,
                        "read",
                        Vec::new(),
                    );
                    audit.fail(&error);
                    return tool_result::<ReadEnvelope, _>(
                        Err(error),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    );
                };
                let path = path.clone();
                let query = query.clone();
                (path, query, Some(cursor))
            }
            None => (
                args.path.unwrap_or_default(),
                args.query.unwrap_or_default(),
                None,
            ),
        };
        self.dispatch_catalogued_read(
            CatalogRead {
                tool,
                operation_id: args.operation_id,
                path,
                query,
                cursor,
                capability,
                redact_output: true,
            },
            extensions,
        )
        .await
    }
}

#[derive(Debug, thiserror::Error)]
enum MistCallError {
    #[error("{0}")]
    UnknownOperation(String),
    #[error("{0}")]
    WrongCapability(String),
    #[error("{0}")]
    Authorization(String),
    #[error("the authenticated caller lacks the exact Mist operation/action/target grant")]
    Grant,
    #[error("MSP targets are not supported by the v1 authorization model")]
    MspTarget,
    #[error("the catalogued target is missing or malformed")]
    InvalidTarget,
    #[error("{0}")]
    OrganizationNotConfigured(String),
    #[error("query limit must be an integer from 1 through 100")]
    InvalidLimit,
    #[error("catalog search requires a 1-128 byte query and a result limit from 1 through 50")]
    InvalidSearch,
    #[error("exactly one of org_id or site_id is required")]
    AmbiguousScope,
    #[error(transparent)]
    Mist(#[from] MistError),
}

#[derive(serde::Serialize)]
struct ReadEnvelope {
    operation_id: String,
    target: Option<String>,
    status: u16,
    content_type: &'static str,
    data: serde_json::Value,
    next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page: Option<rustmistmcp_core::MistPageInfo>,
    truncated: bool,
    /// This token's hourly Mist call budget headroom after this call, when
    /// the injected client tracks one.
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_remaining: Option<BudgetStatus>,
}

#[derive(Serialize)]
struct LocalOrgView {
    source: &'static str,
    organizations: Vec<LocalOrg>,
}

#[derive(Serialize)]
struct LocalOrg {
    id: String,
    target: String,
}

impl ReadEnvelope {
    /// Build the envelope a read tool hands back to the model.
    ///
    /// `redact_output` runs `data` through [`mecmcp_redact::redact_json_value`]
    /// before it is wrapped -- this is the single choke point every
    /// catalogued read passes through, so it is where the Mist device's own
    /// WLAN PSKs, RADIUS/SNMP secrets, API keys, and gateway-template tunnel
    /// PSKs get scrubbed before a model ever sees them. See [`CatalogRead::redact_output`]
    /// for why a handful of internal-only callers pass `false`.
    fn from_response(
        response: rustmistmcp_core::MistResponse,
        target: Option<&MistTarget>,
        budget_remaining: Option<BudgetStatus>,
        redact_output: bool,
    ) -> Self {
        let (content_type, mut data) = match response.body {
            MistResponseBody::Json(value) => ("application/json", value),
            MistResponseBody::Text(value) => ("text/plain; charset=utf-8", value.into()),
            MistResponseBody::Binary(value) => (
                "application/octet-stream",
                serde_json::Value::Array(value.into_iter().map(serde_json::Value::from).collect()),
            ),
            MistResponseBody::Empty => ("application/octet-stream", serde_json::Value::Null),
        };
        if redact_output {
            mecmcp_redact::redact_json_value(&mut data);
        }
        let next_cursor = response
            .cursor
            .and_then(|cursor| serde_json::to_vec(&cursor).ok().map(hex::encode));
        let page = response.page.filter(|page| !page.is_empty());
        Self {
            operation_id: response.operation_id,
            target: target.map(MistTarget::subject),
            status: response.status,
            content_type,
            data,
            next_cursor,
            page,
            truncated: false,
            budget_remaining,
        }
    }
}

/// Map a caller to the Mist hourly call budget pool it may draw from.
///
/// Only a token the server has verified declares `ActorType::Human` may draw
/// on the reserve: an absent caller, an `Agent` actor, or an untagged legacy
/// token (`ActorType::Unknown`) all get [`CallPriority::Standard`], since
/// granting the reserve on anything less than a verified human claim would
/// let an ordinary agent call starve the reserve it exists to protect.
fn call_priority_for(caller: Option<&CallerCtx<MistGrant>>) -> CallPriority {
    match caller {
        Some(caller) if caller.actor_type == mecmcp_auth::ActorType::Human => {
            CallPriority::Reserved
        }
        _ => CallPriority::Standard,
    }
}

fn target_for(
    selectors: &[TargetSelector],
    path: &BTreeMap<String, String>,
) -> Result<Option<MistTarget>, MistCallError> {
    match selectors {
        [TargetSelector::None] => Ok(None),
        [TargetSelector::Org] => path
            .get("org_id")
            .ok_or(MistCallError::InvalidTarget)
            .and_then(|id| MistTarget::org(id).map_err(|_| MistCallError::InvalidTarget))
            .map(Some),
        [TargetSelector::Site] => path
            .get("site_id")
            .ok_or(MistCallError::InvalidTarget)
            .and_then(|id| MistTarget::site(id).map_err(|_| MistCallError::InvalidTarget))
            .map(Some),
        selectors if selectors.contains(&TargetSelector::Msp) => Err(MistCallError::MspTarget),
        _ => Err(MistCallError::InvalidTarget),
    }
}

fn authorize_grant(
    caller: Option<&CallerCtx<MistGrant>>,
    operation_id: &str,
    action: MistCapability,
    target: Option<&MistTarget>,
) -> Result<(), MistCallError> {
    let Some(caller) = caller else {
        return if action == MistCapability::OrdinaryRead {
            Ok(())
        } else {
            Err(MistCallError::Grant)
        };
    };
    let Some(grant) = &caller.grant else {
        return if action == MistCapability::OrdinaryRead {
            Ok(())
        } else {
            Err(MistCallError::Grant)
        };
    };
    if !grant.allows_operation(operation_id)
        || !grant.actions.contains(&action)
        || target.is_some_and(|target| !grant.allows_target(target))
    {
        return Err(MistCallError::Grant);
    }
    Ok(())
}

fn validate_page_limit(query: &BTreeMap<String, serde_json::Value>) -> Result<(), MistCallError> {
    let Some(limit) = query.get("limit") else {
        return Ok(());
    };
    if limit
        .as_u64()
        .is_some_and(|limit| (1..=100).contains(&limit))
    {
        Ok(())
    } else {
        Err(MistCallError::InvalidLimit)
    }
}

fn named_maps<T: Serialize>(args: T, path_names: &[&str]) -> Result<NamedMaps, MistCallError> {
    let object = serde_json::to_value(args)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(MistCallError::InvalidTarget)?;
    let mut path = BTreeMap::new();
    let mut query = BTreeMap::new();
    for (name, value) in object {
        if value.is_null() {
            continue;
        }
        if path_names.contains(&name.as_str()) {
            let value = value.as_str().ok_or(MistCallError::InvalidTarget)?;
            path.insert(name, value.to_owned());
        } else {
            query.insert(name, value);
        }
    }
    Ok((path, query))
}

#[derive(Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct GetOrgArgs {
    /// Organization UUID.
    org_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct InvokeReadArgs {
    /// Exact catalog operation ID.
    operation_id: String,
    /// Catalogued path parameters.
    #[serde(default)]
    path: Option<BTreeMap<String, String>>,
    /// Catalogued query parameters.
    #[serde(default)]
    query: Option<BTreeMap<String, serde_json::Value>>,
    /// Opaque operation-bound continuation.
    #[serde(default)]
    #[schemars(length(min = 2, max = 262_144))]
    cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SearchCapability {
    OrdinaryRead,
    PrivilegedRead,
}

impl From<SearchCapability> for MistCapability {
    fn from(value: SearchCapability) -> Self {
        match value {
            SearchCapability::OrdinaryRead => Self::OrdinaryRead,
            SearchCapability::PrivilegedRead => Self::PrivilegedRead,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SearchTarget {
    None,
    Org,
    Site,
    Msp,
}

impl From<SearchTarget> for TargetSelector {
    fn from(value: SearchTarget) -> Self {
        match value {
            SearchTarget::None => Self::None,
            SearchTarget::Org => Self::Org,
            SearchTarget::Site => Self::Site,
            SearchTarget::Msp => Self::Msp,
        }
    }
}

/// Whether a stats tool returns records or a count distribution.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum StatsModeArg {
    /// Return matching records.
    #[default]
    Records,
    /// Return a count distribution. The response shape differs from records.
    Count,
}

impl From<StatsModeArg> for wan::StatsMode {
    fn from(value: StatsModeArg) -> Self {
        match value {
            StatsModeArg::Records => Self::Records,
            StatsModeArg::Count => Self::Count,
        }
    }
}

/// Which SLE impact view a caller wants.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SleImpactArg {
    /// Gateways impacted by the metric.
    Gateways,
    /// Applications impacted by the metric.
    Applications,
    /// Aggregate impact summary.
    Summary,
}

impl From<SleImpactArg> for wan::SleImpact {
    fn from(value: SleImpactArg) -> Self {
        match value {
            SleImpactArg::Gateways => Self::Gateways,
            SleImpactArg::Applications => Self::Applications,
            SleImpactArg::Summary => Self::Summary,
        }
    }
}

/// Where a caller wants the application list from.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum AppSourceArg {
    /// Applications observed at a site. Requires `site_id`.
    Site,
    /// The constant gateway application catalog. Takes no scope.
    Catalog,
}

impl From<AppSourceArg> for wan::AppSource {
    fn from(value: AppSourceArg) -> Self {
        match value {
            AppSourceArg::Site => Self::Site,
            AppSourceArg::Catalog => Self::Catalog,
        }
    }
}

/// A WAN edge configuration object type.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WanObjectArg {
    /// A LAN segment / network.
    Network,
    /// An application or service definition.
    Service,
    /// A service (SD-WAN steering) policy.
    ServicePolicy,
    /// A gateway template.
    GatewayTemplate,
    /// A device profile. Org scope only.
    DeviceProfile,
}

impl From<WanObjectArg> for wan::WanObject {
    fn from(value: WanObjectArg) -> Self {
        match value {
            WanObjectArg::Network => Self::Network,
            WanObjectArg::Service => Self::Service,
            WanObjectArg::ServicePolicy => Self::ServicePolicy,
            WanObjectArg::GatewayTemplate => Self::GatewayTemplate,
            WanObjectArg::DeviceProfile => Self::DeviceProfile,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchOperationsArgs {
    #[schemars(length(min = 1, max = 128))]
    query: String,
    capability: Option<SearchCapability>,
    target: Option<SearchTarget>,
    #[schemars(range(min = 1, max = 50))]
    limit: Option<u8>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationSchemaArgs {
    operation_id: String,
}

#[derive(Serialize)]
struct OperationSummary<'a> {
    operation_id: &'a str,
    summary: &'a str,
    method: &'a str,
    path: &'a str,
    capability: MistCapability,
    target_selectors: &'a [TargetSelector],
    pagination: rustmistmcp_core::PaginationMode,
}

macro_rules! read_args {
    ($name:ident { $($(#[$meta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Deserialize, JsonSchema, Serialize)]
        #[serde(deny_unknown_fields)]
        struct $name {
            $(
                $(#[$meta])*
                $field: $ty,
            )*
        }
    };
}

/// Which write a change set performs.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum WriteVerbArg {
    /// Create a new object.
    Create,
    /// Update an existing object.
    Update,
}

impl From<WriteVerbArg> for wan_write::WriteVerb {
    fn from(value: WriteVerbArg) -> Self {
        match value {
            WriteVerbArg::Create => Self::Create,
            WriteVerbArg::Update => Self::Update,
        }
    }
}

read_args!(PlanChangeArgs {
    /// Which configuration object type to change. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Create or update. Not sent to Mist.
    #[serde(skip_serializing)]
    verb: WriteVerbArg,
    /// Organization UUID.
    org_id: String,
    /// The object's UUID. Required for `update`, omitted for `create`.
    #[serde(skip_serializing)]
    object_id: Option<String>,
    /// Fields to change. Merged onto the object's current state: arrays
    /// replace wholesale, and a null value deletes the field.
    #[serde(skip_serializing)]
    patch: serde_json::Value,
});

read_args!(GetChangeSetArgs {
    /// Change-set identifier (64 hex characters).
    change_set_id: String,
    /// Which configuration object type. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// The object's UUID. Required for update change sets.
    #[serde(skip_serializing)]
    object_id: Option<String>,
});

read_args!(ApproveChangeSetArgs {
    /// Change-set identifier (64 hex characters).
    change_set_id: String,
    /// The plan digest the approver was shown (from `plan_mist_change` or
    /// `get_mist_change_set`). mecmcp's `ChangesetCoordinator::approve_change_set`
    /// refuses the approval unless this matches the stored digest exactly, so an
    /// approver who echoes the wrong digest -- or none -- cannot approve.
    plan_digest: String,
    /// Which configuration object type. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// The object's UUID. Required for update change sets.
    #[serde(skip_serializing)]
    object_id: Option<String>,
});

read_args!(ApplyChangeSetArgs {
    /// Change-set identifier (64 hex characters).
    change_set_id: String,
    /// Which configuration object type. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// The object's UUID. Required for update change sets.
    #[serde(skip_serializing)]
    object_id: Option<String>,
});

read_args!(OrgPageArgs {
    org_id: String,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    #[schemars(range(min = 1))]
    page: Option<u32>,
});
read_args!(SiteArgs { site_id: String });
read_args!(InventoryArgs {
    org_id: String, #[schemars(range(min = 1, max = 100))] limit: Option<u32>, mac: Option<String>, magic: Option<String>,
    master: Option<String>, model: Option<String>, name: Option<String>,
    search_after: Option<String>, serial: Option<String>, site_id: Option<String>,
    sku: Option<String>, sort: Option<String>, status: Option<String>, text: Option<String>,
    #[serde(rename = "type")] r#type: Option<String>, version: Option<String>,
});
read_args!(SiteDeviceArgs {
    site_id: String,
    device_id: String
});
read_args!(DeviceStatsArgs {
    site_id: String, device_id: String, fields: Option<String>,
});
read_args!(SitePageArgs {
    site_id: String,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    #[schemars(range(min = 1))] page: Option<u32>,
});
read_args!(ClientSearchArgs {
    site_id: String, ap: Option<String>, band: Option<String>, device: Option<String>,
    duration: Option<String>, end: Option<String>, hostname: Option<String>, ip: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>, mac: Option<String>, model: Option<String>, os: Option<String>,
    psk_id: Option<String>, psk_name: Option<String>, search_after: Option<String>,
    sort: Option<String>, ssid: Option<String>, start: Option<String>, text: Option<String>,
    username: Option<String>, vlan: Option<String>,
});
read_args!(EventSearchArgs {
    site_id: String, duration: Option<String>, end: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    search_after: Option<String>, sort: Option<String>, start: Option<String>,
    #[serde(rename = "type")] r#type: Option<String>,
});
read_args!(AlarmSearchArgs {
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)] mode: StatsModeArg,
    ack_admin_name: Option<String>, acked: Option<bool>,
    duration: Option<String>, end: Option<String>, group: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    search_after: Option<String>, severity: Option<String>, sort: Option<String>,
    start: Option<String>, #[serde(rename = "type")] r#type: Option<String>,
});
read_args!(AuditSearchArgs {
    org_id: String, admin_name: Option<String>, duration: Option<String>, end: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>, message: Option<String>,
    #[schemars(range(min = 1))] page: Option<u32>, site_id: Option<String>,
    sort: Option<String>, start: Option<String>,
});
read_args!(SleMetricsArgs {
    site_id: String,
    scope: String,
    scope_id: String,
});
read_args!(SleArgs {
    site_id: String, scope: String, scope_id: String, metric: String,
    duration: Option<String>, end: Option<String>, start: Option<String>,
});
read_args!(SleImpactArgs {
    /// Site UUID.
    site_id: String,
    /// SLE scope, e.g. `site`.
    scope: String,
    /// Identifier for the chosen scope.
    scope_id: String,
    /// SLE metric name.
    metric: String,
    /// Which impact view to return. Not sent to Mist.
    #[serde(skip_serializing)]
    impact: SleImpactArg,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
});
read_args!(InsightArgs {
    site_id: String, metrics: String, duration: Option<String>, end: Option<String>,
    interval: Option<String>, #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    #[schemars(range(min = 1))] page: Option<u32>, start: Option<String>,
});
read_args!(TroubleshootArgs {
    site_id: String, ap: Option<String>, app: Option<String>, duration: Option<String>,
    end: Option<String>, #[schemars(range(min = 1, max = 100))] limit: Option<u32>,
    mac: Option<String>, meeting_id: Option<String>,
    #[schemars(range(min = 1))] page: Option<u32>, start: Option<String>, wired: Option<bool>,
});
read_args!(RogueArgs {
    site_id: String, duration: Option<String>, end: Option<String>, interval: Option<String>,
    #[schemars(range(min = 1, max = 100))] limit: Option<u32>, start: Option<String>,
    #[serde(rename = "type")] r#type: Option<String>,
});
read_args!(UpgradeArgs { site_id: String, status: Option<String> });

/// The device type this tool is permitted to enumerate.
fn gateway_device_type() -> String {
    "gateway".to_owned()
}

read_args!(WanEdgeListArgs {
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    hostname: Option<String>,
    mac: Option<String>,
    model: Option<String>,
    version: Option<String>,
    /// Always `gateway`. Not caller-settable: this tool must not enumerate
    /// APs or switches.
    #[serde(rename = "type", skip_deserializing, default = "gateway_device_type")]
    #[schemars(skip)]
    r#type: String,
});

read_args!(WanEdgeStatsArgs {
    /// Site UUID.
    site_id: String,
    /// Gateway device UUID. When present, returns per-device insight metrics.
    device_id: Option<String>,
    /// Metrics to retrieve. Required when `device_id` is present.
    metrics: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
});

read_args!(TunnelSearchArgs {
    /// Organization UUID.
    org_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(PeerPathSearchArgs {
    /// Organization UUID.
    org_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(BgpPeerSearchArgs {
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(ServicePathEventArgs {
    /// Site UUID.
    site_id: String,
    /// Records or count distribution. Not sent to Mist.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    search_after: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    duration: Option<String>,
    distinct: Option<String>,
});

read_args!(ApplicationListArgs {
    /// Where to read applications from. Not sent to Mist.
    #[serde(skip_serializing)]
    source: AppSourceArg,
    /// Site UUID. Required when `source` is `site`.
    site_id: Option<String>,
    /// Records or count distribution. Ignored for the constant catalog.
    #[serde(default, skip_serializing)]
    mode: StatsModeArg,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    distinct: Option<String>,
});

read_args!(WanConfigListArgs {
    /// Which configuration object type to list. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Organization UUID. Mutually exclusive with `site_id`.
    org_id: Option<String>,
    /// Site UUID for the derived listing. Mutually exclusive with `org_id`.
    site_id: Option<String>,
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    #[schemars(range(min = 1))]
    page: Option<u32>,
});

read_args!(WanConfigGetArgs {
    /// Which configuration object type to read. Not sent to Mist.
    #[serde(skip_serializing)]
    object: WanObjectArg,
    /// Organization UUID.
    org_id: String,
    /// The object's own UUID. Not sent to Mist under this name.
    #[serde(skip_serializing)]
    object_id: String,
});

#[tool_router(router = mist_tool_router, vis = "pub(crate)")]
impl MistHandler {
    #[tool(
        name = "get_mist_device",
        description = "Get one site device. Secret-bearing fields (PSKs, shared secrets, API keys/tokens) are redacted from the response; structural fields and non-secret metadata are preserved."
    )]
    async fn get_mist_device(
        &self,
        Parameters(args): Parameters<SiteDeviceArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_device",
                "getSiteDevice",
                args,
                &["site_id", "device_id"],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_device_stats",
        description = "Get one site device's statistics."
    )]
    async fn get_mist_device_stats(
        &self,
        Parameters(args): Parameters<DeviceStatsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_device_stats",
                "getSiteDeviceStats",
                args,
                &["site_id", "device_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(name = "get_mist_insight", description = "Get site insight metrics.")]
    async fn get_mist_insight(
        &self,
        Parameters(args): Parameters<InsightArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_insight",
                "getSiteInsightMetrics",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_operation_schema",
        description = "Get locally catalogued Mist operation metadata."
    )]
    async fn get_mist_operation_schema(
        &self,
        Parameters(args): Parameters<OperationSchemaArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_mist_operation_schema",
            "read_local",
            Vec::new(),
        );
        if let Err(error) =
            authorize_call(caller, "get_mist_operation_schema", None, RESTRICTED_TOOLS)
        {
            audit.deny("scope");
            return Ok(tool_result::<&MistOperation, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }
        let operation = self.catalog.operation(&args.operation_id);
        match operation {
            Some(operation) => Ok(audited_tool_result(
                &mut audit,
                Ok::<_, MistCallError>(operation),
            )),
            None => {
                audit.deny("catalog");
                Ok(tool_result::<&MistOperation, _>(
                    Err(MistCallError::UnknownOperation(format!(
                        "operation {} is not in the catalog (pinned Mist OpenAPI snapshot: revision {})",
                        args.operation_id,
                        &self.catalog.source.revision[..8.min(self.catalog.source.revision.len())]
                    ))),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ))
            }
        }
    }
    #[tool(name = "get_mist_org", description = "Get one Mist organization.")]
    async fn get_mist_org(
        &self,
        Parameters(args): Parameters<GetOrgArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "get_mist_org",
                    operation_id: "getOrg".to_owned(),
                    path: BTreeMap::from([("org_id".to_owned(), args.org_id)]),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                    redact_output: true,
                },
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_rrm",
        description = "Get current site channel planning."
    )]
    async fn get_mist_rrm(
        &self,
        Parameters(args): Parameters<SiteArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_rrm",
                "getSiteCurrentChannelPlanning",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_self",
        description = "Get the privileged Mist caller profile."
    )]
    async fn get_mist_self(
        &self,
        Parameters(args): Parameters<EmptyArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_self",
                "getSelf",
                args,
                &[],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(name = "get_mist_site", description = "Get one Mist site.")]
    async fn get_mist_site(
        &self,
        Parameters(args): Parameters<SiteArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_site",
                "getSiteInfo",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(name = "get_mist_sle", description = "Get one site SLE summary.")]
    async fn get_mist_sle(
        &self,
        Parameters(args): Parameters<SleArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "get_mist_sle",
                "getSiteSleSummaryTrend",
                args,
                &["site_id", "scope", "scope_id", "metric"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_sle_impact",
        description = "Get gateways, applications, or the summary impacted by one site SLE metric."
    )]
    async fn get_mist_sle_impact(
        &self,
        Parameters(args): Parameters<SleImpactArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::sle_impact(args.impact.into());
        Ok(self
            .dispatch_named(
                "get_mist_sle_impact",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_wan_config",
        description = "Get one WAN edge configuration object by ID. Secret-bearing fields (gateway-template tunnel PSKs, shared secrets, API keys/tokens) are redacted from the response; structural fields and non-secret metadata are preserved."
    )]
    async fn get_mist_wan_config(
        &self,
        Parameters(args): Parameters<WanConfigGetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let object: wan::WanObject = args.object.into();
        let resolved = wan::get_config(object);
        let path = BTreeMap::from([
            ("org_id".to_owned(), args.org_id),
            (wan::object_id_name(object).to_owned(), args.object_id),
        ]);
        // Gateway templates and device profiles are privileged config.
        let capability = match args.object {
            WanObjectArg::GatewayTemplate | WanObjectArg::DeviceProfile => {
                MistCapability::PrivilegedRead
            }
            _ => MistCapability::OrdinaryRead,
        };
        Ok(self
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "get_mist_wan_config",
                    operation_id: resolved.operation_id.to_owned(),
                    path,
                    query: BTreeMap::new(),
                    cursor: None,
                    capability,
                    redact_output: true,
                },
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "get_mist_wan_edge_stats",
        description = "Get WAN edge gateway metrics for a site, or insight metrics for one gateway."
    )]
    async fn get_mist_wan_edge_stats(
        &self,
        Parameters(args): Parameters<WanEdgeStatsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::wan_edge_stats(args.device_id.is_some());
        Ok(self
            .dispatch_named(
                "get_mist_wan_edge_stats",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "invoke_mist_privileged_read",
        description = "Invoke one privileged read selected only by catalog operation ID. Secret-bearing fields (PSKs, RADIUS/SNMP shared secrets, API keys/tokens) are redacted from the response; structural fields and non-secret metadata are preserved."
    )]
    async fn invoke_mist_privileged_read(
        &self,
        Parameters(args): Parameters<InvokeReadArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .invoke_dispatcher(
                "invoke_mist_privileged_read",
                args,
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "invoke_mist_read",
        description = "Invoke one ordinary read selected by catalog operation ID. The `path` and `query` parameters are maps (e.g., path={\"org_id\": \"...\"}, query={\"limit\": 10}), not top-level parameters like the named workflow tools. Secret-bearing fields (PSKs, RADIUS/SNMP shared secrets, API keys/tokens) are redacted from the response; structural fields and non-secret metadata are preserved."
    )]
    async fn invoke_mist_read(
        &self,
        Parameters(args): Parameters<InvokeReadArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .invoke_dispatcher(
                "invoke_mist_read",
                args,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_applications",
        description = "List applications seen at a site, count them, or list the gateway application catalog."
    )]
    async fn list_mist_applications(
        &self,
        Parameters(args): Parameters<ApplicationListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if matches!(args.source, AppSourceArg::Site) && args.site_id.is_none() {
            return Ok(tool_result::<ReadEnvelope, _>(
                Err(MistCallError::AmbiguousScope),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }
        let resolved = wan::applications(args.source.into(), args.mode.into());
        Ok(self
            .dispatch_named(
                "list_mist_applications",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_orgs",
        description = "List the bounded local configured organization view."
    )]
    async fn list_mist_orgs(
        &self,
        Parameters(_): Parameters<EmptyArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(caller, "list_mist_orgs", "read_local", Vec::new());
        if let Err(error) = authorize_call(caller, "list_mist_orgs", None, RESTRICTED_TOOLS) {
            audit.deny("scope");
            return Ok(tool_result::<LocalOrgView, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }
        let organizations = self
            .allowed_orgs
            .iter()
            .filter_map(|id| {
                let target = format!("org/{id}");
                caller
                    .is_none_or(|caller| caller.devices.allows(&target))
                    .then(|| LocalOrg {
                        id: id.clone(),
                        target,
                    })
            })
            .collect();
        Ok(audited_tool_result(
            &mut audit,
            Ok::<_, MistCallError>(LocalOrgView {
                source: "local_configured_allowlist",
                organizations,
            }),
        ))
    }
    #[tool(
        name = "list_mist_rogues",
        description = "List site rogue access points."
    )]
    async fn list_mist_rogues(
        &self,
        Parameters(args): Parameters<RogueArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_rogues",
                "listSiteRogueAPs",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_sites",
        description = "List sites in one organization."
    )]
    async fn list_mist_sites(
        &self,
        Parameters(args): Parameters<OrgPageArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_sites",
                "listOrgSites",
                args,
                &["org_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_sle_metrics",
        description = "List SLE metrics for one site scope."
    )]
    async fn list_mist_sle_metrics(
        &self,
        Parameters(args): Parameters<SleMetricsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_sle_metrics",
                "listSiteSlesMetrics",
                args,
                &["site_id", "scope", "scope_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_upgrades",
        description = "List site device upgrades."
    )]
    async fn list_mist_upgrades(
        &self,
        Parameters(args): Parameters<UpgradeArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_upgrades",
                "listSiteDeviceUpgrades",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_wan_config",
        description = "List WAN edge configuration objects: networks, services, service policies, gateway templates, or device profiles. Secret-bearing fields (gateway-template tunnel PSKs, shared secrets, API keys/tokens) are redacted from the response; structural fields and non-secret metadata are preserved."
    )]
    async fn list_mist_wan_config(
        &self,
        Parameters(args): Parameters<WanConfigListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };
        let object = args.object;
        let resolved = wan::list_config(object.into(), scope);
        // Gateway templates and device profiles are privileged config.
        let capability = match object {
            WanObjectArg::GatewayTemplate | WanObjectArg::DeviceProfile => {
                MistCapability::PrivilegedRead
            }
            _ => MistCapability::OrdinaryRead,
        };
        Ok(self
            .dispatch_named(
                "list_mist_wan_config",
                resolved.operation_id,
                args,
                resolved.path_names,
                capability,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_wan_edges",
        description = "List WAN edge gateways (SRX/SSR) in an organization or site."
    )]
    async fn list_mist_wan_edges(
        &self,
        Parameters(args): Parameters<WanEdgeListArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };
        let resolved = wan::wan_edges(scope);
        Ok(self
            .dispatch_named(
                "list_mist_wan_edges",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_wlans",
        description = "List privileged site WLAN configuration. WLAN PSKs and other secret-bearing fields are redacted from the response; structural fields and non-secret metadata (SSID, VLAN, band settings, etc.) are preserved."
    )]
    async fn list_mist_wlans(
        &self,
        Parameters(args): Parameters<SitePageArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_wlans",
                "listSiteWlans",
                args,
                &["site_id"],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_alarms",
        description = "Search organization or site alarms, or count them."
    )]
    async fn search_mist_alarms(
        &self,
        Parameters(args): Parameters<AlarmSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };
        let resolved = wan::alarms(scope, args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_alarms",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "list_mist_alarm_definitions",
        description = "List the constant Mist alarm definition catalog."
    )]
    async fn list_mist_alarm_definitions(
        &self,
        Parameters(args): Parameters<EmptyArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "list_mist_alarm_definitions",
                "listAlarmDefinitions",
                args,
                &[],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_audit_logs",
        description = "Search privileged organization audit logs."
    )]
    async fn search_mist_audit_logs(
        &self,
        Parameters(args): Parameters<AuditSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_audit_logs",
                "listOrgAuditLogs",
                args,
                &["org_id"],
                MistCapability::PrivilegedRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_bgp_peers",
        description = "Search WAN edge BGP peer stats in an organization or site, or count them."
    )]
    async fn search_mist_bgp_peers(
        &self,
        Parameters(args): Parameters<BgpPeerSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let scope = match wan::resolve_scope(args.org_id.as_deref(), args.site_id.as_deref()) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(tool_result::<ReadEnvelope, _>(
                    Err(MistCallError::AmbiguousScope),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };
        let resolved = wan::bgp_peers(scope, args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_bgp_peers",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_clients",
        description = "Search site wireless clients."
    )]
    async fn search_mist_clients(
        &self,
        Parameters(args): Parameters<ClientSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_clients",
                "searchSiteWirelessClients",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_events",
        description = "Search site system events."
    )]
    async fn search_mist_events(
        &self,
        Parameters(args): Parameters<EventSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_events",
                "searchSiteSystemEvents",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_inventory",
        description = "Search organization inventory."
    )]
    async fn search_mist_inventory(
        &self,
        Parameters(args): Parameters<InventoryArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "search_mist_inventory",
                "searchOrgInventory",
                args,
                &["org_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_operations",
        description = "Search bounded locally catalogued Mist operation metadata."
    )]
    async fn search_mist_operations(
        &self,
        Parameters(args): Parameters<SearchOperationsArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(caller, "search_mist_operations", "read_local", Vec::new());
        if let Err(error) = authorize_call(caller, "search_mist_operations", None, RESTRICTED_TOOLS)
        {
            audit.deny("scope");
            return Ok(tool_result::<Vec<OperationSummary<'_>>, _>(
                Err(MistCallError::Authorization(error.to_string())),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }
        let limit = usize::from(args.limit.unwrap_or(20));
        if args.query.is_empty() || args.query.len() > 128 || !(1..=50).contains(&limit) {
            let error = MistCallError::InvalidSearch;
            audit.fail(&error);
            return Ok(tool_result::<Vec<OperationSummary<'_>>, _>(
                Err(error),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }
        let query = args.query.to_ascii_lowercase();
        let capability = args.capability.map(MistCapability::from);
        let target = args.target.map(TargetSelector::from);
        let matches = self
            .catalog
            .operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation.capability,
                    MistCapability::OrdinaryRead | MistCapability::PrivilegedRead
                )
            })
            .filter(|operation| !operation.target_selectors.contains(&TargetSelector::Msp))
            .filter(|operation| capability.is_none_or(|value| operation.capability == value))
            .filter(|operation| {
                target.is_none_or(|value| operation.target_selectors.contains(&value))
            })
            .filter(|operation| {
                operation.operation_id.to_ascii_lowercase().contains(&query)
                    || operation.summary.to_ascii_lowercase().contains(&query)
                    || operation.path.to_ascii_lowercase().contains(&query)
                    || operation
                        .openapi_tags
                        .iter()
                        .any(|tag| tag.to_ascii_lowercase().contains(&query))
            })
            .take(limit)
            .map(|operation| OperationSummary {
                operation_id: &operation.operation_id,
                summary: &operation.summary,
                method: &operation.method,
                path: &operation.path,
                capability: operation.capability,
                target_selectors: &operation.target_selectors,
                pagination: operation.pagination,
            })
            .collect::<Vec<_>>();
        Ok(audited_tool_result(
            &mut audit,
            Ok::<_, MistCallError>(matches),
        ))
    }
    #[tool(
        name = "search_mist_peer_paths",
        description = "Search SD-WAN overlay peer path stats, or count them by a distinct field."
    )]
    async fn search_mist_peer_paths(
        &self,
        Parameters(args): Parameters<PeerPathSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::peer_paths(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_peer_paths",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_service_path_events",
        description = "Search WAN edge service path events for a site, or count them."
    )]
    async fn search_mist_service_path_events(
        &self,
        Parameters(args): Parameters<ServicePathEventArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::service_path_events(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_service_path_events",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "search_mist_tunnels",
        description = "Search WAN edge IPsec tunnel stats, or count them by a distinct field."
    )]
    async fn search_mist_tunnels(
        &self,
        Parameters(args): Parameters<TunnelSearchArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let resolved = wan::tunnels(args.mode.into());
        Ok(self
            .dispatch_named(
                "search_mist_tunnels",
                resolved.operation_id,
                args,
                resolved.path_names,
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
    #[tool(
        name = "plan_mist_change",
        description = "Stage a change set for a WAN edge configuration object (network, service, service policy, gateway template, or device profile). Returns a digest-bound plan ready for approval. Arrays replace wholesale; null deletes a field. Secret-bearing fields in the returned `before`/`after` (PSKs, shared secrets, API keys/tokens) are redacted; structural fields and non-secret metadata are preserved. The digest and plan lifecycle operate on the unredacted values, so redaction here never affects what is actually written. A patch containing the literal redaction placeholder is refused: omit a secret field to keep its current value, or supply the real value."
    )]
    async fn plan_mist_change(
        &self,
        Parameters(args): Parameters<PlanChangeArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let owner = match caller {
            Some(ctx) => ctx.token_name.clone(),
            None => "stdio".to_owned(),
        };
        let mut audit = audit_scope(
            caller,
            "plan_mist_change",
            "plan",
            vec![args.org_id.clone()],
        );

        // Reject mist_configured BEFORE anything else.
        if let Err(wan_write::PatchError::MistConfigured) =
            wan_write::reject_config_authority(&args.patch)
        {
            audit.fail("patch sets mist_configured");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(
                    "patch sets mist_configured, which controls who may configure the device",
                ),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        // Reject the redaction placeholder BEFORE anything else: the before/
        // after preview this tool returns redacts secret fields to this same
        // literal, so a model that echoes it back must never have that
        // literal merged into a device write.
        if let Err(wan_write::PatchError::RedactionPlaceholder) =
            wan_write::reject_redaction_placeholder(&args.patch)
        {
            audit.fail("patch contains the redaction placeholder");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(
                    "patch contains the redaction placeholder; omit secret fields to keep \
                     their current value (merge-patch preserves omitted keys), or supply the \
                     real value",
                ),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        // Validate org against allowed_orgs before issuing any read or creating a change set.
        if !self
            .allowed_orgs
            .iter()
            .any(|allowed| allowed == &args.org_id)
        {
            audit.deny("org not in allowed_orgs");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "organization {} is not in the server's allowed organizations",
                    args.org_id
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        let object: wan::WanObject = args.object.into();
        let verb: wan_write::WriteVerb = args.verb.into();
        let target = wan_write::write_target(object, verb);

        // For update, read the object; for create, before is null.
        let before = if verb == wan_write::WriteVerb::Update {
            let object_id = match args.object_id.as_deref() {
                Some(id) => id,
                None => {
                    audit.fail("update requires object_id");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("update requires object_id"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };

            let mut path = PathValues::new();
            path.insert(target.id_path_name.to_owned(), object_id.to_owned());
            path.insert("org_id".to_owned(), args.org_id.clone());

            let read = CatalogRead {
                tool: "plan_mist_change",
                operation_id: target.read_operation_id.to_owned(),
                path,
                query: QueryValues::new(),
                cursor: None,
                capability: if target.privileged {
                    MistCapability::PrivilegedRead
                } else {
                    MistCapability::OrdinaryRead
                },
                // Internal: `data` feeds `merge_patch` below to build the
                // actual device write body. Redacting it here would splice
                // "[REDACTED]" into the write. The `before`/`after` this
                // produces are redacted separately before they reach the
                // model-facing response.
                redact_output: false,
            };

            let result = self.dispatch_catalogued_read(read, &extensions).await;
            if result.is_error == Some(true) {
                audit.fail("read failed");
                return Ok(result);
            }

            let text = match result.content[0].as_text() {
                Some(text_content) => text_content.text.clone(),
                None => {
                    audit.fail("read result was not text");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("read result was not text"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse read response: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!(
                            "failed to parse read response: {error}"
                        )),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            match value.get("data") {
                Some(data) => data.clone(),
                None => {
                    audit.fail("read response missing data field");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("read response missing data field"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            }
        } else {
            serde_json::Value::Null
        };

        let after = wan_write::merge_patch(&before, &args.patch);

        let staged = match change_set::stage_plan(
            &self.coordinator,
            owner.clone(),
            object,
            args.object_id.as_deref(),
            args.org_id.clone(),
            before.clone(),
            after.clone(),
        )
        .await
        {
            Ok(staged) => staged,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };

        // The change was proposed. Emitted here rather than inside the
        // coordinator because this server stages through `insert_change_set`,
        // which mecmcp does not treat as a lifecycle event.
        if let Some(recorder) = &self.evidence {
            recorder.proposal(
                &staged.change_set_id,
                &staged.change_set_id,
                &change_set::object_key(object, args.object_id.as_deref()),
                &owner,
                &staged.plan_digest,
            );
        }

        // Auto-waive if lab mode is enabled
        if self.lab_mode {
            let device = change_set::object_key(object, args.object_id.as_deref());
            if let Err(error) = self
                .coordinator
                .waive_approval(
                    staged.change_set_id.clone(),
                    device,
                    owner.clone(),
                    staged.plan_digest.clone(),
                )
                .await
            {
                audit.fail(format!("lab mode waive failed: {error}"));
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(format!("lab mode waive failed: {error}")),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        }

        // `staged.before`/`staged.after` came from the unredacted internal
        // read above (needed raw for `merge_patch`); redact each own copy
        // now, at the point they join a response the model will see.
        let mut redacted_after = staged.after.clone();
        mecmcp_redact::redact_json_value(&mut redacted_after);

        let response = if before.is_null() {
            serde_json::json!({
                "change_set_id": staged.change_set_id,
                "plan_digest": staged.plan_digest,
                "preview_digest": staged.preview_digest,
                "before": null,
                "before_state": "absent (create)",
                "after": redacted_after,
            })
        } else {
            let mut redacted_before = staged.before.clone();
            mecmcp_redact::redact_json_value(&mut redacted_before);
            serde_json::json!({
                "change_set_id": staged.change_set_id,
                "plan_digest": staged.plan_digest,
                "preview_digest": staged.preview_digest,
                "before": redacted_before,
                "after": redacted_after,
            })
        };

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    #[tool(
        name = "get_mist_change_set",
        description = "Inspect a staged change set, returning its state, owner, before/after, and approval status. Secret-bearing fields in `before`/`after` (PSKs, shared secrets, API keys/tokens) are redacted; structural fields and non-secret metadata are preserved."
    )]
    async fn get_mist_change_set(
        &self,
        Parameters(args): Parameters<GetChangeSetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_mist_change_set",
            "read",
            vec![args.change_set_id.clone()],
        );

        let object: wan::WanObject = args.object.into();
        let device = change_set::object_key(object, args.object_id.as_deref());

        let record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };

        // Extract before/after from the preview artifact
        let (before, after) = if let Some(preview) = &record.preview {
            let parsed: serde_json::Value = match serde_json::from_str(&preview.artifact) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse preview: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!("failed to parse preview: {error}")),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            let mut before_value = parsed
                .get("before")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let mut after_value = parsed
                .get("after")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            // The stored preview artifact is the raw, unredacted plan (it
            // must stay that way so a later apply can still use it); redact
            // this response's own copy before it reaches the model.
            mecmcp_redact::redact_json_value(&mut before_value);
            mecmcp_redact::redact_json_value(&mut after_value);
            (before_value, after_value)
        } else {
            (serde_json::Value::Null, serde_json::Value::Null)
        };

        // `approver: null` alone does not tell an operator whether a second
        // person reviewed this or whether lab mode waived the requirement.
        // mecmcp's packaging standard requires both fields, so surface the
        // waiver reason alongside the (absent) approver.
        let approval_waiver = record
            .approval
            .as_ref()
            .and_then(|approval| approval.waived.as_ref())
            .map(|waiver| waiver.reason.clone());

        let response = serde_json::json!({
            "change_set_id": record.id,
            "state": record.state.as_str(),
            "owner": record.owner,
            "approver": record.approver,
            "approval_waiver": approval_waiver,
            "plan_digest": record.digest,
            "before": before,
            "after": after,
        });

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    /// Record that a write which reached Mist **definitively** did not succeed.
    ///
    /// Only for outcomes Mist itself reported -- a response that arrived and
    /// was unusable. A request that was sent and then timed out is *not* one of
    /// these: Mist may have applied it, and saying otherwise is false evidence.
    ///
    /// Every terminal path after a *received* response has to emit one. Mist may already
    /// have created or changed the object by the time the response turns out to
    /// be unusable, so a branch that returns without a receipt leaves the chain
    /// ending at apply intent -- an attempt with no outcome, which says someone
    /// must go and look while saying nothing about what to look for.
    fn failure_receipt(
        &self,
        request_id: &str,
        principal: &str,
        record: &mecmcp_changeset::ChangeSetRecord,
        reason: &str,
    ) {
        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.result_receipt(
                request_id,
                &record.id,
                &record.device,
                principal,
                false,
                reason,
            )
        {
            tracing::error!(
                %error,
                change_set_id = %record.id,
                "the write was answered but its failure receipt could not be persisted"
            );
        }
    }

    #[tool(
        name = "approve_mist_change_set",
        description = "Grant second-principal approval to a planned change set. The approver must be distinct from the owner."
    )]
    async fn approve_mist_change_set(
        &self,
        Parameters(args): Parameters<ApproveChangeSetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        let approver = match caller {
            Some(ctx) => ctx.token_name.clone(),
            None => "stdio".to_owned(),
        };
        // Truthful, not permissive: a stdio caller carries no verified token
        // entry, so its actor type is unknown rather than assumed human. mecmcp's
        // `approve_change_set` refuses anything but `Human` (mecmcp#390, the
        // house rule that a human approves), which is exactly the outcome an
        // unattributed caller should get.
        let approver_actor_type = change_set::actor_type(caller);
        let mut audit = audit_scope(
            caller,
            "approve_mist_change_set",
            "approve",
            vec![args.change_set_id.clone()],
        );

        let object: wan::WanObject = args.object.into();
        let device = change_set::object_key(object, args.object_id.as_deref());

        // Routed through mecmcp's own lifecycle API rather than a self-managed
        // `change_set` fetch + mutate + `update_change_set` write. The
        // coordinator enforces, in order: the digest format is well-formed, the
        // change set exists for this device, the approver is distinct from the
        // owner, the approver is a verified human principal, the change set is
        // still `Planned`, the approval window has not expired, and the
        // `plan_digest` the caller echoed back matches the stored digest exactly
        // -- a change set cannot be committed by an approver who never saw (or
        // misquoted) the plan.
        let output = match self
            .coordinator
            .approve_change_set(
                args.change_set_id.clone(),
                device,
                approver.clone(),
                args.plan_digest.clone(),
                approver_actor_type,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                // `field() == "change_set_id"` covers both "not found" and the
                // self-approval refusal; only the latter is a deny rather than a
                // plain failure, so match the message the coordinator uses for it.
                if error.field() == "change_set_id" && error.message().contains("own plan") {
                    audit.deny("self-approval");
                } else {
                    audit.fail(error.to_string());
                }
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };

        // The coordinator itself already recorded the `Approval` evidence entry
        // (mecmcp `ChangesetCoordinator::approve_change_set`, after its state
        // write) since it now owns the lifecycle transition. Recording it again
        // here would double the approval entry in the hash-chained evidence log.

        let response = serde_json::json!({
            "change_set_id": output.change_set_id,
            "state": "approved",
            "expires_in_seconds": self.coordinator.approval_ttl().as_secs(),
        });

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    #[tool(
        name = "apply_mist_change_set",
        description = "Apply an approved change set to Mist. Verifies approval, checks for drift, issues the mutation, and verifies the result."
    )]
    async fn apply_mist_change_set(
        &self,
        Parameters(args): Parameters<ApplyChangeSetArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<MistGrant>(&extensions);
        // Who is applying, which need not be who planned. The apply path does
        // not require caller == owner, so recording `record.owner` here would
        // attribute the execution to the planner -- a false statement in a
        // trail whose whole purpose is saying who did what.
        let applying_principal =
            caller.map_or_else(|| "stdio".to_owned(), |ctx| ctx.token_name.clone());
        // `request_id` is the join key transport audit uses, so it must name
        // *this call*. Putting the change-set id there makes two attempts on one
        // set indistinguishable and breaks correlation with the tool call that
        // actually did it.
        let apply_request_id =
            caller.map_or_else(|| "stdio".to_owned(), |ctx| ctx.request_id.to_string());
        let mut audit = audit_scope(
            caller,
            "apply_mist_change_set",
            "apply",
            vec![args.change_set_id.clone()],
        );

        let object: wan::WanObject = args.object.into();
        let device = change_set::object_key(object, args.object_id.as_deref());

        // Step 1: Take the device guard for concurrency control.
        let cancellation = tokio_util::sync::CancellationToken::new();
        let _guard = match self.coordinator.device_guard(&device, &cancellation).await {
            Ok(guard) => guard,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };

        // Step 2: Fetch the record and refuse unless state is Approved.
        let mut record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };

        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            audit.fail(format!(
                "change set is {}, not approved",
                record.state.as_str()
            ));
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "change set is {}, not approved",
                    record.state.as_str()
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        // Step 3: Check if the approval has expired.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| {
                audit.fail(format!("time error: {error}"));
                rmcp::ErrorData::invalid_params(format!("time error: {error}"), None)
            })?
            .as_secs();

        if now > record.expires_at_unix {
            audit.fail("approval has expired");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "approval expired at unix timestamp {}",
                    record.expires_at_unix
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        // Extract before/after/org_id from the preview artifact.
        let (_before, after, org_id) = if let Some(preview) = &record.preview {
            let parsed: serde_json::Value = match serde_json::from_str(&preview.artifact) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse preview: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!("failed to parse preview: {error}")),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            let before_value = parsed
                .get("before")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let after_value = parsed
                .get("after")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let org_id_value = match parsed.get("org_id").and_then(|v| v.as_str()) {
                Some(id) => id.to_owned(),
                None => {
                    audit.fail("preview missing org_id");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(
                            "change set was planned before org-scope fix and must be re-planned",
                        ),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            (before_value, after_value, org_id_value)
        } else {
            audit.fail("change set has no preview");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>("change set has no preview"),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        };

        // Determine the verb from the expected fingerprint.
        let is_create = record.expected_candidate_fingerprint == "create";
        let verb = if is_create {
            wan_write::WriteVerb::Create
        } else {
            wan_write::WriteVerb::Update
        };
        let target = wan_write::write_target(object, verb);

        // Validate and bind object_id for updates.
        let object_id = if !is_create {
            match args.object_id.as_deref() {
                Some(id) => id.to_owned(),
                None => {
                    audit.fail("update requires object_id");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("update requires object_id"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            }
        } else {
            String::new() // Placeholder for creates; will be populated from response
        };

        // Step 4: For updates, re-read the object and compare fingerprints.
        let drift_checked = if !is_create {
            let mut path = PathValues::new();
            path.insert(target.id_path_name.to_owned(), object_id.clone());
            path.insert("org_id".to_owned(), org_id.clone());

            let read = CatalogRead {
                tool: "apply_mist_change_set",
                operation_id: target.read_operation_id.to_owned(),
                path,
                query: QueryValues::new(),
                cursor: None,
                capability: if target.privileged {
                    MistCapability::PrivilegedRead
                } else {
                    MistCapability::OrdinaryRead
                },
                // Internal: the drift fingerprint is a SHA-256 over this
                // exact device state. Redacting it first would fold every
                // secret-bearing object down to the same "[REDACTED]"
                // fingerprint and blind drift detection to a real device
                // change. Never returned to the model.
                redact_output: false,
            };

            let result = self.dispatch_catalogued_read(read, &extensions).await;
            if result.is_error == Some(true) {
                audit.fail("drift check read failed");
                return Ok(result);
            }

            let text = match result.content[0].as_text() {
                Some(text_content) => text_content.text.clone(),
                None => {
                    audit.fail("drift check result was not text");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("drift check result was not text"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to parse drift check response: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!(
                            "failed to parse drift check response: {error}"
                        )),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            let current = match value.get("data") {
                Some(data) => data.clone(),
                None => {
                    audit.fail("drift check response missing data field");
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("drift check response missing data field"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };

            // Compute fingerprint of current state.
            let canonical = match serde_json::to_vec(&current) {
                Ok(v) => v,
                Err(error) => {
                    audit.fail(format!("failed to serialize current state: {error}"));
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>(format!(
                            "failed to serialize current state: {error}"
                        )),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            };
            let mut hasher = sha2::Sha256::new();
            hasher.update(&canonical);
            let current_fingerprint = format!("sha256:{}", hex::encode(hasher.finalize()));

            // Compare with expected fingerprint.
            if current_fingerprint != record.expected_candidate_fingerprint {
                // `Approved -> Failed` is not a legal edge under mecmcp 0.22.0's
                // transition policy, so this cannot settle directly any more:
                // the write would be refused and swallowed into the audit line
                // below, leaving the record `Approved` and the drifted approval
                // still spendable. Claim it first -- nothing has been sent to
                // Mist, and the claim gives the settle a legal
                // `Applying -> Failed` while spending the approval, which is
                // the point: a drifted plan must not be retried.
                //
                // `Expected` here, not `None`, and for the opposite reason to
                // the apply below. The marker decides how a crash is read back:
                // handleless means "the outcome is unknown, leave it `Applying`
                // and have a human look", its absence means "nothing is in
                // flight, settle it `Failed`". On this branch nothing was sent,
                // so `Failed` is the true outcome and the recovery that
                // produces it is the correct one. Handleless would strand a
                // record known not to have run, blocking further plans for the
                // object.
                match self
                    .coordinator
                    .claim_change_set_for_apply(
                        &record.id,
                        &record.device,
                        mecmcp_changeset::ApplyHandle::Expected,
                    )
                    .await
                {
                    Ok(mut claimed) => {
                        claimed.state = mecmcp_changeset::ChangeSetState::Failed;
                        if let Err(error) = self.coordinator.update_change_set(claimed).await {
                            audit.fail(format!("failed to mark drift failure: {error}"));
                        } else {
                            audit.fail("object moved since planning (drift detected)");
                        }
                    }
                    Err(error) => {
                        audit.fail(format!(
                            "object moved since planning (drift detected), and the change set \
                             could not be claimed to record that: {error}"
                        ));
                    }
                }
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(
                        "object has been modified since planning; fingerprint mismatch",
                    ),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
            true
        } else {
            false
        };

        // Validate org against allowed_orgs before issuing the write.
        if !self.allowed_orgs.iter().any(|allowed| allowed == &org_id) {
            audit.deny("org not in allowed_orgs");
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!(
                    "organization {} is not in the server's allowed organizations",
                    org_id
                )),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        // The device is about to be written. Persisted *before* that happens, so
        // a crash during the write still leaves evidence the attempt was made --
        // and refused if it cannot be persisted, because a Mist object changed
        // with no record that anyone tried is the one state this chain exists to
        // rule out.
        //
        // Emitted **before** the `Applying` transition below, not after. After
        // it, a refusal would leave the record in `Applying` while telling the
        // caller it is still approved -- and the retry gate accepts only
        // `Approved`, so the change set would be stranded with no Mist write and
        // no way forward. Refusing here leaves it exactly as it was.
        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.apply_intent(
                &apply_request_id,
                &record.id,
                &record.device,
                &applying_principal,
            )
        {
            let message = format!(
                "apply refused: the apply-intent evidence record could not be persisted \
                 ({error}); the change set is still approved and can be retried"
            );
            audit.fail(message.clone());
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(message),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        // Step 5: claim the change set before issuing the write.
        //
        // mecmcp 0.22.0 makes `claim_change_set_for_apply` the only legal
        // `Approved -> Applying` transition, and it does the read and the write
        // under one lock, so two applies cannot both read `Approved` and both
        // issue the write. The plain `update_change_set` this used to do is now
        // refused outright.
        //
        // `None`: a Mist write is synchronous and returns no pollable handle,
        // so a crash mid-apply leaves an outcome only the service knows. That
        // is what `apply_without_handle` records, and it keeps the record
        // honestly unresolved rather than asserting an outcome nobody saw.
        record = match self
            .coordinator
            .claim_change_set_for_apply(
                &record.id,
                &record.device,
                mecmcp_changeset::ApplyHandle::None,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                audit.fail(error.to_string());
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(error.to_string()),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };

        // Step 6: Issue the write with json: Some(after).
        let mut path = PathValues::new();
        path.insert("org_id".to_owned(), org_id.clone());
        if !is_create {
            path.insert(target.id_path_name.to_owned(), object_id.clone());
        }

        let write_request = MistRequest {
            operation_id: target.write_operation_id.to_owned(),
            path,
            query: QueryValues::new(),
            json: Some(after.clone()),
            cursor: None,
        };

        let write_result = self
            .client
            .execute_as(write_request, call_priority_for(caller))
            .await;
        let write_response = match write_result {
            Ok(response) => response,
            Err(error) => {
                audit.fail(format!("write failed: {error}"));
                // Deliberately **no** receipt here. This branch covers a
                // request that was sent and then failed -- a timeout, an
                // oversized body, a read error partway through the response --
                // so Mist may well have applied the mutation. A failure receipt
                // would state that it did not, which is materially false
                // evidence and worse than none: it tells an auditor the change
                // did not happen when it may have.
                //
                // Leaving the chain at apply intent is the honest encoding of
                // "attempted, outcome unknown, someone must go and look". It is
                // indistinguishable from a crash between intent and receipt,
                // and that is correct -- both mean exactly that.
                tracing::error!(
                    %error,
                    change_set_id = %record.id,
                    "the Mist write failed after the request was sent; the outcome is \
                     indeterminate and no result receipt is emitted"
                );
                record.state = mecmcp_changeset::ChangeSetState::Failed;
                let _ = self.coordinator.update_change_set(record).await;
                return Ok(tool_result::<serde_json::Value, _>(
                    Err::<serde_json::Value, _>(format!("write failed: {error}")),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                ));
            }
        };

        // Step 7: Re-read and verify against after.
        let final_object_id = if is_create {
            // Extract the ID from the write response.
            match &write_response.body {
                MistResponseBody::Json(json) => match json.get("id") {
                    Some(serde_json::Value::String(id)) => id.clone(),
                    _ => {
                        audit.fail("create response missing id field");
                        self.failure_receipt(
                            &apply_request_id,
                            &applying_principal,
                            &record,
                            "create response missing id field",
                        );
                        record.state = mecmcp_changeset::ChangeSetState::Failed;
                        let _ = self.coordinator.update_change_set(record).await;
                        return Ok(tool_result::<serde_json::Value, _>(
                            Err::<serde_json::Value, _>("create response missing id field"),
                            ResultFormat::PrettyJson,
                            RESULT_LIMITS,
                            OutputRedaction::Apply,
                        ));
                    }
                },
                _ => {
                    audit.fail("create response was not JSON");
                    self.failure_receipt(
                        &apply_request_id,
                        &applying_principal,
                        &record,
                        "create response was not JSON",
                    );
                    record.state = mecmcp_changeset::ChangeSetState::Failed;
                    let _ = self.coordinator.update_change_set(record).await;
                    return Ok(tool_result::<serde_json::Value, _>(
                        Err::<serde_json::Value, _>("create response was not JSON"),
                        ResultFormat::PrettyJson,
                        RESULT_LIMITS,
                        OutputRedaction::Apply,
                    ));
                }
            }
        } else {
            object_id.clone()
        };

        let mut verify_path = PathValues::new();
        verify_path.insert(target.id_path_name.to_owned(), final_object_id.clone());
        verify_path.insert("org_id".to_owned(), org_id.clone());

        let verify_read = CatalogRead {
            tool: "apply_mist_change_set",
            operation_id: target.read_operation_id.to_owned(),
            path: verify_path,
            query: QueryValues::new(),
            cursor: None,
            capability: if target.privileged {
                MistCapability::PrivilegedRead
            } else {
                MistCapability::OrdinaryRead
            },
            // Internal: compared byte-for-byte against `after` below to
            // confirm the write landed. Never returned to the model.
            redact_output: false,
        };

        let verify_result = self
            .dispatch_catalogued_read(verify_read, &extensions)
            .await;
        let verified = if verify_result.is_error != Some(true) {
            if let Some(text_content) = verify_result.content[0].as_text() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text_content.text) {
                    if let Some(data) = value.get("data") {
                        data == &after
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Mist answered. Recorded before the local state write, because that
        // write can fail and the receipt describes what the device did, which
        // local persistence cannot retract. A failure is recorded as fully as a
        // success.
        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.result_receipt(
                &apply_request_id,
                &record.id,
                &record.device,
                &applying_principal,
                verified,
                if verified { "" } else { "write not verified" },
            )
        {
            tracing::error!(
                %error,
                change_set_id = %record.id,
                "Mist answered but the result receipt could not be persisted; the \
                 evidence chain ends at apply intent"
            );
        }

        // Step 8: Mark Applied or Failed and persist.
        record.state = if verified {
            mecmcp_changeset::ChangeSetState::Applied
        } else {
            mecmcp_changeset::ChangeSetState::Failed
        };

        if let Err(error) = self.coordinator.update_change_set(record.clone()).await {
            audit.fail(format!("failed to persist final state: {error}"));
            return Ok(tool_result::<serde_json::Value, _>(
                Err::<serde_json::Value, _>(format!("failed to persist final state: {error}")),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ));
        }

        let response = serde_json::json!({
            "change_set_id": args.change_set_id,
            "state": record.state.as_str(),
            "object_id": final_object_id,
            "drift_checked": drift_checked,
            "verified": verified,
        });

        Ok(audited_tool_result::<serde_json::Value, &str>(
            &mut audit,
            Ok(response),
        ))
    }

    #[tool(
        name = "troubleshoot_mist",
        description = "List site troubleshoot calls."
    )]
    async fn troubleshoot_mist(
        &self,
        Parameters(args): Parameters<TroubleshootArgs>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(self
            .dispatch_named(
                "troubleshoot_mist",
                "listSiteTroubleshootCalls",
                args,
                &["site_id"],
                MistCapability::OrdinaryRead,
                &extensions,
            )
            .await)
    }
}

/// Wrap a filtered tool list in the result shape a 2026-07-28 client accepts.
///
/// `ListToolsResult::with_all_items` leaves `ttl_ms` and `cache_scope` unset and
/// both are omitted on the wire; a client on that protocol validates the result
/// and rejects it, which surfaces as "tools fetch failed" against a server that
/// is healthy and answering in milliseconds. Servers that do not override
/// `list_tools` get these from rmcp's generated handler — this one filters by
/// scope, so it supplies them itself.
///
/// Gated on the negotiated version exactly as rmcp does: the fields belong to
/// 2026-07-28 and later, and a strict legacy client rejects what it did not
/// negotiate.
///
/// `private` where rmcp's unfiltered list says `public`, because this list is
/// per token: a cache keyed only on the URL must not serve one caller's
/// permitted surface to another.
fn listed_tools(tools: Vec<rmcp::model::Tool>, cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if cache_hints {
        listed
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MistHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rustmistmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "HPE Juniper Mist MCP server. Read tools dominate the surface; batch-1 \
                 WAN edge mutations exist only behind the plan_mist_change -> \
                 approve_mist_change_set -> apply_mist_change_set lifecycle, and \
                 approval must come from a principal other than the planner. Use \
                 named workflows first; catalog dispatchers accept operation IDs, \
                 never methods or URLs.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = mecmcp_server::caller_from_extensions::<rustmistmcp_core::MistGrant>(
            &context.extensions,
        );
        let tools = self.tool_router.list_all();
        let visible = if caller.is_some() {
            filter_tools_for_scope(tools, caller, RESTRICTED_TOOLS)
        } else {
            tools
                .into_iter()
                .filter(|tool| !RESTRICTED_TOOLS.contains(&tool.name.as_ref()))
                .collect()
        };
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both
        // are omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // `private`: the list is per token, so a cache keyed only on the URL
        // must not serve one caller's surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(visible, cache_hints))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mecmcp_audit::testutil::CapturingWriter;
    use mecmcp_auth::{ActorType, ScopeSet};
    use std::{
        cell::RefCell,
        io::Write,
        sync::{Mutex, OnceLock},
    };

    thread_local! {
        static ACTIVE_AUDIT_CAPTURE: RefCell<Option<CapturingWriter>> = const { RefCell::new(None) };
    }

    static AUDIT_SUBSCRIBER: OnceLock<()> = OnceLock::new();

    struct ThreadLocalAuditWriter(Option<CapturingWriter>);

    impl Write for ThreadLocalAuditWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match &mut self.0 {
                Some(capture) => capture.write(buf),
                None => std::io::sink().write(buf),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            match &mut self.0 {
                Some(capture) => capture.flush(),
                None => std::io::sink().flush(),
            }
        }
    }

    struct ThreadLocalAuditMakeWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadLocalAuditMakeWriter {
        type Writer = ThreadLocalAuditWriter;

        fn make_writer(&'a self) -> Self::Writer {
            ThreadLocalAuditWriter(ACTIVE_AUDIT_CAPTURE.with(|capture| capture.borrow().clone()))
        }
    }

    struct AuditCaptureGuard;

    impl Drop for AuditCaptureGuard {
        fn drop(&mut self) {
            ACTIVE_AUDIT_CAPTURE.with(|capture| {
                capture.borrow_mut().take();
            });
        }
    }

    fn install_audit_capture(capture: CapturingWriter) -> AuditCaptureGuard {
        AUDIT_SUBSCRIBER.get_or_init(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(ThreadLocalAuditMakeWriter)
                .with_ansi(false)
                .with_target(true)
                .with_max_level(tracing::Level::INFO)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("test audit subscriber is installed once");
        });
        ACTIVE_AUDIT_CAPTURE.with(|active| {
            assert!(
                active.borrow().is_none(),
                "nested audit capture on one test thread"
            );
            *active.borrow_mut() = Some(capture);
        });
        AuditCaptureGuard
    }

    #[derive(Default)]
    struct RecordingClient(Mutex<Vec<MistRequest>>);

    struct FixedResponseClient {
        response: rustmistmcp_core::MistResponse,
    }

    #[async_trait]
    impl MistClient for RecordingClient {
        async fn execute(
            &self,
            request: MistRequest,
        ) -> Result<rustmistmcp_core::MistResponse, MistError> {
            self.0.lock().expect("recorder").push(request.clone());
            Ok(rustmistmcp_core::MistResponse {
                operation_id: request.operation_id,
                status: 200,
                body: MistResponseBody::Json(serde_json::json!({"name": "authorized"})),
                cursor: None,
                page: None,
            })
        }
    }

    #[async_trait]
    impl MistClient for FixedResponseClient {
        async fn execute(
            &self,
            _request: MistRequest,
        ) -> Result<rustmistmcp_core::MistResponse, MistError> {
            Ok(self.response.clone())
        }
    }

    fn org_read(operation_id: &str) -> CatalogRead {
        CatalogRead {
            tool: "invoke_mist_read",
            operation_id: operation_id.to_owned(),
            path: BTreeMap::from([(
                "org_id".to_owned(),
                "11111111-1111-1111-1111-111111111111".to_owned(),
            )]),
            query: BTreeMap::new(),
            cursor: None,
            capability: MistCapability::OrdinaryRead,
            redact_output: true,
        }
    }

    fn caller(target: &str) -> CallerCtx<MistGrant> {
        CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "alice".to_owned(),
            devices: ScopeSet::Allowlist(vec![target.to_owned()]),
            tools: ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]),
            grant: Some(MistGrant {
                allowed_operations: vec!["getOrg".to_owned()],
                actions: vec![MistCapability::OrdinaryRead],
                subjects: vec![MistTarget::parse(target).expect("target")],
            }),
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        }
    }

    /// A caller with a given token name and actor type, and no grant. Used by
    /// the change-set write tools (`plan_mist_change`, `approve_mist_change_set`),
    /// which key their owner/approver distinctness and human-actor checks off
    /// `token_name`/`actor_type` rather than a `MistGrant`.
    fn caller_named(token_name: &str, actor_type: ActorType) -> CallerCtx<MistGrant> {
        CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: token_name.to_owned(),
            devices: ScopeSet::Allowlist(vec![
                "org/11111111-1111-1111-1111-111111111111".to_owned(),
            ]),
            tools: ScopeSet::Allowlist(vec![
                "plan_mist_change".to_owned(),
                "approve_mist_change_set".to_owned(),
            ]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type,
            client_name: None,
            model_id: None,
            session_id: None,
        }
    }

    fn extensions(caller: CallerCtx<MistGrant>) -> rmcp::model::Extensions {
        let request = http::Request::new(());
        let (mut parts, _) = request.into_parts();
        parts.extensions.insert(caller);
        let mut extensions = rmcp::model::Extensions::new();
        extensions.insert(parts);
        extensions
    }

    #[tokio::test]
    async fn authenticated_ordinary_read_does_not_require_a_mutation_grant() {
        let target = "org/11111111-1111-1111-1111-111111111111";
        let client = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            client.clone(),
        )
        .expect("handler");
        let mut caller = caller(target);
        caller.grant = None;

        let result = handler
            .dispatch_catalogued_read(org_read("getOrg"), &extensions(caller))
            .await;

        assert_ne!(result.is_error, Some(true), "{result:?}");
        assert_eq!(client.0.lock().expect("recorder").len(), 1);
    }

    #[tokio::test]
    async fn authenticated_privileged_dispatch_requires_an_exact_mist_grant() {
        let client = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            client.clone(),
        )
        .expect("handler");
        let caller = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "privileged-without-grant".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["invoke_mist_privileged_read".to_owned()]),
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };

        let result = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_privileged_read",
                    operation_id: "getSelf".to_owned(),
                    path: BTreeMap::new(),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::PrivilegedRead,
                    redact_output: true,
                },
                &extensions(caller),
            )
            .await;

        assert_eq!(result.is_error, Some(true), "{result:?}");
        assert!(
            client.0.lock().expect("recorder").is_empty(),
            "privileged request must be denied before client dispatch"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_dispatch_cursor_emits_a_failed_audit_outcome() {
        let handler = MistHandler::blocked(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
        )
        .expect("handler");
        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());
        let result = handler
            .invoke_dispatcher(
                "invoke_mist_read",
                InvokeReadArgs {
                    operation_id: "getOrg".to_owned(),
                    path: None,
                    query: None,
                    cursor: Some("not-hex".to_owned()),
                },
                MistCapability::OrdinaryRead,
                &rmcp::model::Extensions::new(),
            )
            .await;
        assert_eq!(result.is_error, Some(true));
        let output = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
        assert!(output.contains("tool=invoke_mist_read"), "{output}");
        assert!(output.contains("result=error"), "{output}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn page_limit_headers_are_surfaced_to_the_tool_caller() {
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            Arc::new(FixedResponseClient {
                response: rustmistmcp_core::MistResponse {
                    operation_id: "listOrgSites".to_owned(),
                    status: 200,
                    body: MistResponseBody::Json(serde_json::json!([{"name": "site-a"}])),
                    cursor: None,
                    page: Some(rustmistmcp_core::MistPageInfo {
                        page: Some(1),
                        limit: Some(1),
                        total: Some(2),
                    }),
                },
            }),
        )
        .expect("handler");
        let result = handler
            .dispatch_catalogued_read(org_read("listOrgSites"), &rmcp::model::Extensions::new())
            .await;
        assert_ne!(result.is_error, Some(true), "{result:?}");
        let text = result.content[0]
            .as_text()
            .expect("text content")
            .text
            .clone();
        let body: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(body["page"]["page"], 1);
        assert_eq!(body["page"]["limit"], 1);
        assert_eq!(body["page"]["total"], 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cursor_shape_bounds_are_enforced_before_client_dispatch() {
        let recorder = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        for cursor in [
            "0".to_owned(),
            "gg".to_owned(),
            "0".repeat(MAX_ENCODED_CURSOR_BYTES + 1),
        ] {
            let result = handler
                .invoke_dispatcher(
                    "invoke_mist_read",
                    InvokeReadArgs {
                        operation_id: "getOrg".to_owned(),
                        path: None,
                        query: None,
                        cursor: Some(cursor),
                    },
                    MistCapability::OrdinaryRead,
                    &rmcp::model::Extensions::new(),
                )
                .await;
            assert_eq!(result.is_error, Some(true), "{result:?}");
        }
        assert!(recorder.0.lock().expect("recorder").is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cursor_context_is_reauthorized_on_every_continuation() {
        let recorder = Arc::new(RecordingClient::default());
        let requested_org = "11111111-1111-1111-1111-111111111111";
        let other_org = "44444444-4444-4444-4444-444444444444";
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec![requested_org.to_owned(), other_org.to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        let path = BTreeMap::from([("org_id".to_owned(), requested_org.to_owned())]);
        let cursor = rustmistmcp_core::MistCursor::new(
            "listOrgSites".to_owned(),
            &Url::parse("https://api.mist.com/").expect("origin"),
            rustmistmcp_core::PaginationMode::PageLimit,
            "2".to_owned(),
        )
        .expect("cursor")
        .with_request_context(
            path,
            BTreeMap::from([("limit".to_owned(), serde_json::json!(25))]),
            Some(MistTarget::org(requested_org).expect("target")),
        )
        .expect("context");
        let encoded = hex::encode(serde_json::to_vec(&cursor).expect("serialize"));
        let result = handler
            .invoke_dispatcher(
                "invoke_mist_read",
                InvokeReadArgs {
                    operation_id: "listOrgSites".to_owned(),
                    path: None,
                    query: None,
                    cursor: Some(encoded),
                },
                MistCapability::OrdinaryRead,
                &extensions(caller(&format!("org/{other_org}"))),
            )
            .await;
        assert_eq!(result.is_error, Some(true));
        assert!(recorder.0.lock().expect("recorder").is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn crafted_cursor_cannot_reach_an_org_outside_the_allowlist() {
        // Regression guard: a continuation naming an org outside the
        // allowlist must never reach the Mist client.
        let recorder = Arc::new(RecordingClient::default());
        let allowed_org = "11111111-1111-1111-1111-111111111111";
        let outside_org = "99999999-9999-9999-9999-999999999999";
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec![allowed_org.to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        let path = BTreeMap::from([("org_id".to_owned(), outside_org.to_owned())]);
        let crafted_cursor = rustmistmcp_core::MistCursor::new(
            "listOrgSites".to_owned(),
            &Url::parse("https://api.mist.com/").expect("origin"),
            rustmistmcp_core::PaginationMode::PageLimit,
            "2".to_owned(),
        )
        .expect("cursor")
        .with_request_context(
            path,
            BTreeMap::from([("limit".to_owned(), serde_json::json!(25))]),
            Some(MistTarget::org(outside_org).expect("target")),
        )
        .expect("context");
        let encoded = hex::encode(serde_json::to_vec(&crafted_cursor).expect("serialize"));
        let result = handler
            .invoke_dispatcher(
                "invoke_mist_read",
                InvokeReadArgs {
                    operation_id: "listOrgSites".to_owned(),
                    path: None,
                    query: None,
                    cursor: Some(encoded),
                },
                MistCapability::OrdinaryRead,
                &rmcp::model::Extensions::new(),
            )
            .await;
        assert_eq!(result.is_error, Some(true), "{result:?}");
        let text = result.content[0]
            .as_text()
            .expect("text content")
            .text
            .clone();
        assert!(
            text.contains("not in the configured allowlist"),
            "expected an allowlist denial, got: {text}"
        );
        assert!(
            recorder.0.lock().expect("recorder").is_empty(),
            "the outside-allowlist continuation must never reach the Mist client"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_tool_target_and_grant_authority_is_audited_before_client_dispatch() {
        let recorder = Arc::new(RecordingClient::default());
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());
        let path = BTreeMap::from([(
            "org_id".to_owned(),
            "11111111-1111-1111-1111-111111111111".to_owned(),
        )]);
        let allowed = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_read",
                    operation_id: "getOrg".to_owned(),
                    path: path.clone(),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                    redact_output: true,
                },
                &extensions(caller("org/11111111-1111-1111-1111-111111111111")),
            )
            .await;
        assert_ne!(allowed.is_error, Some(true), "{allowed:?}");
        assert_eq!(recorder.0.lock().expect("recorder").len(), 1);

        let denied = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_read",
                    operation_id: "getOrg".to_owned(),
                    path,
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                    redact_output: true,
                },
                &extensions(caller("org/44444444-4444-4444-4444-444444444444")),
            )
            .await;
        assert_eq!(denied.is_error, Some(true));
        assert_eq!(recorder.0.lock().expect("recorder").len(), 1);

        let output = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
        assert!(output.contains("result=ok"), "{output}");
        assert!(output.contains("result=denied"), "{output}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_grant_cannot_dispatch_an_undiscovered_site() {
        let recorder = Arc::new(RecordingClient::default());
        let org_id = "11111111-1111-1111-1111-111111111111";
        let site_id = "44444444-4444-4444-4444-444444444444";
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec![org_id.to_owned()],
            BTreeMap::new(),
            recorder.clone(),
        )
        .expect("handler");
        let target = format!("site/{site_id}");
        let caller = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "alice".to_owned(),
            devices: ScopeSet::Allowlist(vec![target.clone()]),
            tools: ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]),
            grant: Some(MistGrant {
                allowed_operations: vec!["getSiteInfo".to_owned()],
                actions: vec![MistCapability::OrdinaryRead],
                subjects: vec![MistTarget::parse(&target).expect("target")],
            }),
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };
        let result = handler
            .dispatch_catalogued_read(
                CatalogRead {
                    tool: "invoke_mist_read",
                    operation_id: "getSiteInfo".to_owned(),
                    path: BTreeMap::from([("site_id".to_owned(), site_id.to_owned())]),
                    query: BTreeMap::new(),
                    cursor: None,
                    capability: MistCapability::OrdinaryRead,
                    redact_output: true,
                },
                &extensions(caller),
            )
            .await;
        assert_eq!(result.is_error, Some(true));
        assert!(recorder.0.lock().expect("recorder").is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mismatched_and_non_success_responses_are_failed_audits() {
        let cases = [
            rustmistmcp_core::MistResponse {
                operation_id: "getSiteInfo".to_owned(),
                status: 200,
                body: MistResponseBody::Json(serde_json::json!({"name": "wrong operation"})),
                cursor: None,
                page: None,
            },
            rustmistmcp_core::MistResponse {
                operation_id: "getOrg".to_owned(),
                status: 403,
                body: MistResponseBody::Json(serde_json::json!({"detail": "forbidden"})),
                cursor: None,
                page: None,
            },
            rustmistmcp_core::MistResponse {
                operation_id: "getOrg".to_owned(),
                status: 429,
                body: MistResponseBody::Json(serde_json::json!({"detail": "slow down"})),
                cursor: None,
                page: None,
            },
        ];
        for response in cases {
            let handler = MistHandler::with_client(
                "https://api.mist.com/",
                vec!["11111111-1111-1111-1111-111111111111".to_owned()],
                BTreeMap::new(),
                Arc::new(FixedResponseClient { response }),
            )
            .expect("handler");
            let capture = CapturingWriter::default();
            let _capture_guard = install_audit_capture(capture.clone());
            let result = handler
                .dispatch_catalogued_read(org_read("getOrg"), &rmcp::model::Extensions::new())
                .await;
            assert_eq!(result.is_error, Some(true), "{result:?}");
            let output =
                String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
            assert!(output.contains("result=error"), "{output}");
            assert!(!output.contains("result=ok"), "{output}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_result_refusal_is_a_failed_audit() {
        let sites = (0..32)
            .map(|_| serde_json::json!({"name": "x".repeat(20_000)}))
            .collect();
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            Arc::new(FixedResponseClient {
                response: rustmistmcp_core::MistResponse {
                    operation_id: "listOrgSites".to_owned(),
                    status: 200,
                    body: MistResponseBody::Json(serde_json::Value::Array(sites)),
                    cursor: None,
                    page: None,
                },
            }),
        )
        .expect("handler");
        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());
        let result = handler
            .dispatch_catalogued_read(org_read("listOrgSites"), &rmcp::model::Extensions::new())
            .await;
        assert_eq!(result.is_error, Some(true), "{result:?}");
        let output = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("UTF-8");
        assert!(output.contains("result=error"), "{output}");
        assert!(!output.contains("result=ok"), "{output}");
    }

    #[test]
    fn wildcard_tool_scope_excludes_every_restricted_read() {
        let handler = MistHandler::blocked(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
        )
        .expect("handler");
        let caller = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "wildcard".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };
        let visible = filter_tools_for_scope(
            handler.tool_router.list_all(),
            Some(&caller),
            RESTRICTED_TOOLS,
        );
        let names = visible
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        for restricted in RESTRICTED_TOOLS {
            assert!(!names.contains(restricted), "{restricted}");
        }
    }

    /// `search_mist_operations` is pure catalog introspection: describing an
    /// operation and being allowed to invoke it are different privileges. A
    /// caller scoped only to the search tool itself (no `invoke_mist_read` or
    /// `invoke_mist_privileged_read`, no [`MistGrant`]) must still see every
    /// catalogued operation matching the query, mirroring the same fix
    /// already applied to `get_mist_operation_schema`.
    #[tokio::test]
    async fn search_mist_operations_does_not_require_execution_scope() {
        let handler = MistHandler::blocked(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
        )
        .expect("handler");
        let introspection_only = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "introspection-only".to_owned(),
            devices: ScopeSet::Allowlist(Vec::new()),
            tools: ScopeSet::Allowlist(vec!["search_mist_operations".to_owned()]),
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };

        let result = handler
            .search_mist_operations(
                Parameters(SearchOperationsArgs {
                    query: "getself".to_owned(),
                    capability: Some(SearchCapability::PrivilegedRead),
                    target: None,
                    limit: None,
                }),
                extensions(introspection_only),
            )
            .await
            .expect("call succeeds");

        assert_ne!(result.is_error, Some(true), "{result:?}");
        let text = result.content[0]
            .as_text()
            .expect("text content")
            .text
            .clone();
        let matches: Vec<serde_json::Value> = serde_json::from_str(&text).expect("valid JSON");
        assert!(
            matches
                .iter()
                .any(|operation| operation["operation_id"] == "getSelf"),
            "a token with no invoke_mist_privileged_read scope and no grant must still \
             discover the privileged getSelf operation by search: {matches:?}"
        );
    }

    #[tokio::test]
    async fn search_mist_operations_only_returns_invocable_reads() {
        let handler = MistHandler::blocked(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
        )
        .expect("handler");
        let introspection_only = CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "introspection-only".to_owned(),
            devices: ScopeSet::Allowlist(Vec::new()),
            tools: ScopeSet::Allowlist(vec!["search_mist_operations".to_owned()]),
            grant: None::<MistGrant>,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        };

        let result = handler
            .search_mist_operations(
                Parameters(SearchOperationsArgs {
                    query: "org".to_owned(),
                    capability: None,
                    target: None,
                    limit: Some(50),
                }),
                extensions(introspection_only),
            )
            .await
            .expect("call succeeds");

        assert_ne!(result.is_error, Some(true), "{result:?}");
        let text = result.content[0]
            .as_text()
            .expect("text content")
            .text
            .clone();
        let matches: Vec<serde_json::Value> = serde_json::from_str(&text).expect("valid JSON");
        assert!(
            !matches.is_empty(),
            "search must surface invocable read operations, not just an empty list"
        );
        for operation in &matches {
            let capability = operation["capability"]
                .as_str()
                .expect("capability is a string");
            assert!(
                capability == "ordinary_read" || capability == "privileged_read",
                "search must not surface non-read operations that invoke_mist_read/invoke_mist_privileged_read cannot dispatch: {operation:?}"
            );
            let targets = operation["target_selectors"]
                .as_array()
                .expect("target_selectors is an array");
            assert!(
                !targets.iter().any(|target| target == "msp"),
                "search must not surface MSP-targeted operations that dispatch_named rejects: {operation:?}"
            );
        }
    }

    #[test]
    fn handler_reuses_strict_mist_regional_endpoint_validation() {
        for endpoint in [
            "https://evil.example/",
            "https://127.0.0.1/",
            "https://api.mist.com:8443/",
            "https://api.mist.com/api/v1/",
        ] {
            assert!(
                MistHandler::blocked(
                    endpoint,
                    vec!["11111111-1111-1111-1111-111111111111".to_owned()],
                    BTreeMap::new(),
                )
                .is_err(),
                "{endpoint}"
            );
        }
        assert!(
            MistHandler::blocked(
                "https://api.eu.mist.com/",
                vec!["11111111-1111-1111-1111-111111111111".to_owned()],
                BTreeMap::new(),
            )
            .is_ok()
        );
    }

    /// Regression test for audit capture race: a noisy thread emitting audit
    /// events without a capture subscriber must not poison the callsite interest
    /// cache and break the main thread's capture.
    ///
    /// This test exercises the real `install_audit_capture` helper to verify
    /// the global subscriber + thread-local writer design survives concurrent
    /// emissions from uncaptured threads. A reversion to the naive
    /// `tracing::subscriber::set_default(fmt().with_writer(cap))` pattern would
    /// fail this test with an empty capture.
    ///
    /// # Placement rationale
    ///
    /// This test shares the process with other audit tests. That's intentional:
    /// the correct design (global subscriber via `set_global_default`, thread-
    /// local writer via `ThreadLocalAuditMakeWriter`) is safe in multi-test
    /// processes. The first test to call `install_audit_capture` installs the
    /// global subscriber; subsequent tests reuse it and only set their thread-
    /// local capture.
    ///
    /// A reversion to thread-local subscribers would make this test fail even in
    /// isolation, but the shared-process placement also catches a subtler bug:
    /// if a noisy thread in one test poisons the callsite cache before another
    /// test's capture is installed, the naive pattern would silently skip events
    /// in the second test. The global-subscriber design immunises against that.
    ///
    /// Note that placing this test in its own integration test binary would NOT
    /// improve coverage—it would just burn CI time running the same assertions
    /// in a fresh process. The race this test guards against is callsite-level,
    /// not process-level.
    #[test]
    fn audit_capture_survives_noisy_uncaptured_thread() {
        use mecmcp_audit::AuditScope;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        // Helper to emit audit events - uses a distinct tool name to avoid
        // callsite conflicts with other tests
        fn emit_audit_event(tool: &'static str) {
            let mut scope = AuditScope::stdio(tool, "read", Vec::new());
            scope.succeed();
        }

        // Start a noisy thread that emits audit events WITHOUT setting up
        // a capture. This thread's emissions must not poison the callsite
        // interest cache.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let noisy_thread = std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                emit_audit_event("audit_race_noise");
                std::thread::yield_now();
            }
        });

        // Give the noisy thread a chance to hit the callsite first
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Now install the capture on THIS thread and emit events
        let capture = CapturingWriter::default();
        let _guard = install_audit_capture(capture.clone());

        // Emit multiple events, yielding to give the noisy thread more chances
        // to interfere
        for _ in 0..50 {
            emit_audit_event("audit_race_captured");
            std::thread::yield_now();
        }

        // Stop the noisy thread
        stop.store(true, Ordering::Relaxed);
        noisy_thread.join().expect("noisy thread panicked");

        // Verify the capture worked - if the naive pattern were used, this
        // would be empty
        let output = String::from_utf8(capture.0.lock().expect("capture").clone())
            .expect("audit output is UTF-8");

        assert!(
            output.contains("tool=audit_race_captured"),
            "audit capture must survive concurrent uncaptured thread emissions; \
             an empty capture indicates the callsite interest cache was poisoned; \
             output: {output}"
        );
        assert!(
            output.contains("result=ok"),
            "captured events must show success; output: {output}"
        );
        // The noisy thread's events should NOT appear in this thread's capture
        assert!(
            !output.contains("tool=audit_race_noise"),
            "noisy thread emissions must not leak into this thread's capture; \
             output: {output}"
        );
    }

    /// Percy's MEC-425 review of PR#124: mecmcp's `ChangesetCoordinator::
    /// approve_change_set` (v0.24.1) already emits an `Approval` evidence
    /// record after its state write. `approve_mist_change_set` used to emit
    /// its own, on top of that, so every approved change set carried two
    /// `Approval` entries in the hash-chained evidence log -- the one fact
    /// two-person control exists to prove. This fails against the pre-fix
    /// handler (count == 2) and passes once the handler's own
    /// `recorder.approval(...)` call is removed.
    #[tokio::test]
    async fn approving_a_change_set_records_exactly_one_approval_evidence_entry() {
        let evidence = Arc::new(mecmcp_audit::recorder::EvidenceRecorder::new(
            mecmcp_audit::recorder::RecorderConfig {
                server_id: "rustmistmcp-test".to_owned(),
                run_id: "approval-dedup".to_owned(),
                resume_from: None,
                records_per_segment: 64,
            },
        ));
        let handler = MistHandler::with_client_and_evidence(
            "https://api.mist.com/",
            vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            BTreeMap::new(),
            Arc::new(RecordingClient::default()),
            evidence.clone(),
        )
        .expect("handler");

        let planned = handler
            .plan_mist_change(
                Parameters(PlanChangeArgs {
                    object: WanObjectArg::Network,
                    verb: WriteVerbArg::Create,
                    org_id: "11111111-1111-1111-1111-111111111111".to_owned(),
                    object_id: None,
                    patch: serde_json::json!({"name": "branch"}),
                }),
                extensions(caller_named("owner", ActorType::Human)),
            )
            .await
            .expect("plan call");
        assert_ne!(planned.is_error, Some(true), "{planned:?}");
        let planned_text = planned.content[0]
            .as_text()
            .expect("plan text content")
            .text
            .clone();
        let planned_json: serde_json::Value =
            serde_json::from_str(&planned_text).expect("plan JSON");
        let change_set_id = planned_json["change_set_id"]
            .as_str()
            .expect("change_set_id")
            .to_owned();
        let plan_digest = planned_json["plan_digest"]
            .as_str()
            .expect("plan_digest")
            .to_owned();

        let approved = handler
            .approve_mist_change_set(
                Parameters(ApproveChangeSetArgs {
                    change_set_id: change_set_id.clone(),
                    plan_digest,
                    object: WanObjectArg::Network,
                    object_id: None,
                }),
                extensions(caller_named("human-approver", ActorType::Human)),
            )
            .await
            .expect("approve call");
        assert_ne!(approved.is_error, Some(true), "{approved:?}");

        let segment = evidence.close_current().expect("closed segment");
        let approval_count = segment
            .records()
            .iter()
            .filter(|record| {
                matches!(
                    record,
                    mecmcp_audit::evidence::EvidenceRecord::Approval(approval)
                        if approval.changeset_id == change_set_id
                )
            })
            .count();
        assert_eq!(
            approval_count, 1,
            "exactly one Approval evidence record must exist per change set, got {approval_count}"
        );
    }
    /// A Mist backend whose response body always carries the same
    /// fixture secrets, regardless of which operation was requested. This is
    /// deliberately shape-agnostic (`ReadEnvelope::from_response` wraps
    /// whatever JSON value it is given; nothing in the dispatch path branches
    /// on body shape), so one fixture stands in for every WLAN, RADIUS, SNMP,
    /// and API-key-bearing device response this server can read.
    struct SecretLeakClient {
        catalog: Arc<Catalog>,
    }

    const FIXTURE_ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
    const FIXTURE_SITE_ID: &str = "22222222-2222-2222-2222-222222222222";
    const FIXTURE_NETWORK_ID: &str = "33333333-3333-3333-3333-333333333333";
    const FIXTURE_DEVICE_ID: &str = "44444444-4444-4444-4444-444444444444";

    const FAKE_WLAN_PSK: &str = "FAKE-WLAN-PSK-9f2b7a11e5";
    const FAKE_RADIUS_SECRET: &str = "FAKE-RADIUS-SECRET-3d81ffec02";
    const FAKE_SNMP_COMMUNITY: &str = "FAKE-SNMP-COMMUNITY-7e0c1a44b6";
    const FAKE_API_KEY: &str = "FAKE-API-KEY-5b6e221019a4";
    const FAKE_BGP_AUTH_KEY: &str = "FAKE-BGP-AUTH-KEY-1a2b3c4d5e";
    const FAKE_OSPF_AUTH_KEY: &str = "FAKE-OSPF-AUTH-KEY-6f7g8h9i0j";
    const FAKE_RADIUS_KEK: &str = "FAKE-RADIUS-KEK-a1b2c3d4e5";
    const FAKE_RADIUS_MACK: &str = "FAKE-RADIUS-MACK-f6g7h8i9j0";
    const FAKE_WEP_KEY: &str = "FAKE-WEP-KEY-0102030405";

    /// Paired with the constant's own name, not its value, so a leak failure
    /// can name which fixture secret leaked without printing the secret
    /// itself into the test log (CodeQL `rust/cleartext-logging`).
    const FIXTURE_SECRETS: &[(&str, &str)] = &[
        ("FAKE_WLAN_PSK", FAKE_WLAN_PSK),
        ("FAKE_RADIUS_SECRET", FAKE_RADIUS_SECRET),
        ("FAKE_SNMP_COMMUNITY", FAKE_SNMP_COMMUNITY),
        ("FAKE_API_KEY", FAKE_API_KEY),
        ("FAKE_BGP_AUTH_KEY", FAKE_BGP_AUTH_KEY),
        ("FAKE_OSPF_AUTH_KEY", FAKE_OSPF_AUTH_KEY),
        ("FAKE_RADIUS_KEK", FAKE_RADIUS_KEK),
        ("FAKE_RADIUS_MACK", FAKE_RADIUS_MACK),
        ("FAKE_WEP_KEY", FAKE_WEP_KEY),
    ];

    /// A fixture marker present on every response this client returns, so a
    /// test can prove a tool actually reached the fixture rather than short-
    /// circuiting (an authorization refusal, an ambiguous-scope error, a
    /// response-schema mismatch) before ever calling `execute`.
    const FIXTURE_MARKER: &str = "branch-fixture";

    fn secret_bearing_fixture() -> serde_json::Value {
        serde_json::json!({
            "id": FIXTURE_NETWORK_ID,
            "name": FIXTURE_MARKER,
            "vlan_id": 10,
            "ip": "203.0.113.5",
            "hostname": "gw1.example.net",
            "psk": FAKE_WLAN_PSK,
            "wlans": [{
                "ssid": "corp",
                "psk": FAKE_WLAN_PSK,
                "auth": {"type": "wep", "keys": [FAKE_WEP_KEY]},
            }],
            "radius_config": {
                "auth_servers": [{
                    "host": "198.51.100.10",
                    "secret": FAKE_RADIUS_SECRET,
                    "keywrap_kek": FAKE_RADIUS_KEK,
                    "keywrap_mack": FAKE_RADIUS_MACK,
                }]
            },
            "snmp_config": {"community": FAKE_SNMP_COMMUNITY},
            "api_token": FAKE_API_KEY,
            "bgp_config": {"peer1": {"auth_key": FAKE_BGP_AUTH_KEY}},
            "ospf_areas": {
                "0.0.0.0": {"networks": [{"network": "10.0.0.0/24", "auth_keys": [FAKE_OSPF_AUTH_KEY]}]}
            },
        })
    }

    /// Resolve a `$ref` against the catalog's own component registry, one
    /// hop at a time, until a schema with no `$ref` is reached.
    fn resolve_schema<'a>(
        catalog: &'a Catalog,
        schema: &'a serde_json::Value,
    ) -> &'a serde_json::Value {
        let mut current = schema;
        while let Some(reference) = current.get("$ref").and_then(serde_json::Value::as_str) {
            let name = reference
                .rsplit('/')
                .next()
                .expect("non-empty $ref pointer");
            current = catalog
                .components
                .get("schemas")
                .and_then(|schemas| schemas.get(name))
                .unwrap_or_else(|| panic!("unresolved $ref: {reference}"));
        }
        current
    }

    /// Whether an operation's declared 200 JSON response is an array, so the
    /// fixture client can hand back an array-shaped body list operations
    /// require instead of failing catalog response-schema validation.
    fn response_is_array_shaped(catalog: &Catalog, operation_id: &str) -> bool {
        let operation = catalog
            .operation(operation_id)
            .unwrap_or_else(|| panic!("{operation_id} is not in the embedded catalog"));
        let Some(schema) = operation
            .responses
            .get("200")
            .and_then(|by_media| by_media.get("application/json"))
        else {
            return false;
        };
        resolve_schema(catalog, schema)
            .get("type")
            .and_then(serde_json::Value::as_str)
            == Some("array")
    }

    #[async_trait]
    impl MistClient for SecretLeakClient {
        async fn execute(
            &self,
            request: MistRequest,
        ) -> Result<rustmistmcp_core::MistResponse, MistError> {
            let body = if response_is_array_shaped(&self.catalog, &request.operation_id) {
                serde_json::Value::Array(vec![secret_bearing_fixture()])
            } else {
                secret_bearing_fixture()
            };
            Ok(rustmistmcp_core::MistResponse {
                operation_id: request.operation_id,
                status: 200,
                body: MistResponseBody::Json(body),
                cursor: None,
                page: None,
            })
        }
    }

    /// A caller with every read-relevant catalog operation this sweep uses,
    /// granted for both capability tiers and both fixture targets. Real
    /// deployments never grant this broadly; here it exists purely to open
    /// every tool this sweep needs, so the redaction proof is not
    /// accidentally reduced by an authorization refusal being mistaken for a
    /// clean (no-secret) result.
    fn full_sweep_caller() -> CallerCtx<MistGrant> {
        const GRANTED_OPERATIONS: &[&str] = &[
            "getSelf",
            "getOrg",
            "listOrgSites",
            "getSiteInfo",
            "searchOrgInventory",
            "getSiteDevice",
            "getSiteDeviceStats",
            "listSiteWlans",
            "searchSiteWirelessClients",
            "searchSiteSystemEvents",
            "searchSiteAlarms",
            "searchOrgAlarms",
            "listAlarmDefinitions",
            "listOrgAuditLogs",
            "listSiteSlesMetrics",
            "getSiteSleSummaryTrend",
            "getSiteSleImpactSummary",
            "getSiteInsightMetrics",
            "listSiteTroubleshootCalls",
            "listSiteRogueAPs",
            "getSiteCurrentChannelPlanning",
            "listSiteDeviceUpgrades",
            "getSiteGatewayMetrics",
            "searchOrgDevices",
            "getOrgNetwork",
            "listOrgNetworks",
            "listGatewayApplications",
            "searchOrgTunnelsStats",
            "searchOrgPeerPathStats",
            "searchOrgBgpStats",
            "searchSiteServicePathEvents",
        ];
        CallerCtx {
            request_id: uuid::Uuid::new_v4(),
            token_name: "redaction-sweep".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(KNOWN_TOOLS.iter().map(|name| (*name).to_owned()).collect()),
            grant: Some(MistGrant {
                allowed_operations: GRANTED_OPERATIONS
                    .iter()
                    .map(|op| (*op).to_owned())
                    .collect(),
                actions: vec![MistCapability::OrdinaryRead, MistCapability::PrivilegedRead],
                subjects: vec![
                    MistTarget::org(FIXTURE_ORG_ID).expect("org target"),
                    MistTarget::site(FIXTURE_SITE_ID).expect("site target"),
                ],
            }),
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            client_name: None,
            model_id: None,
            session_id: None,
        }
    }

    /// Panics naming the tool and leaked secret's constant, rather than a
    /// bare `assert!`, so a failure here points straight at which tool and
    /// which fixture value leaked without needing to re-run under a
    /// debugger. Prints the constant's *name*, not its value or the
    /// surrounding result, so the failure message itself never echoes the
    /// secret into the test log (CodeQL `rust/cleartext-logging`).
    fn assert_no_secret_leak(tool: &str, result: &CallToolResult) {
        let rendered = format!("{result:?}");
        for (name, secret) in FIXTURE_SECRETS {
            assert!(
                !rendered.contains(secret),
                "{tool} leaked fixture secret {name}"
            );
        }
    }

    /// Tools whose result legitimately carries no device data under this
    /// sweep's fixture and single self-approving caller, so a fixture-marker
    /// assertion does not apply to them: `get_mist_operation_schema`/
    /// `search_mist_operations` answer from catalog metadata, not a device
    /// response; `list_mist_orgs` answers from the server's local
    /// configured-org allowlist; `approve_mist_change_set` is correctly
    /// refused because the sweep's single caller is also the plan's owner
    /// (self-approval); `apply_mist_change_set` runs in lab mode, where the
    /// plan was already approved on creation, so it succeeds -- but its
    /// response carries only ids/state, no device data, so it is still
    /// exempt from the fixture-marker check. Its success is asserted
    /// separately, below.
    const NO_DEVICE_DATA_TOOLS: &[&str] = &[
        "get_mist_operation_schema",
        "search_mist_operations",
        "list_mist_orgs",
        "approve_mist_change_set",
        "apply_mist_change_set",
    ];

    /// MEC-710 / F3: a tool-level failure comes back as
    /// `Ok(CallToolResult { is_error: Some(true), .. })`, not `Err`, so
    /// `assert_no_secret_leak` alone passes on a call that never reached the
    /// fixture at all -- proving nothing about redaction. This asserts the
    /// call actually succeeded and that the fixture's own marker shows up in
    /// the output, for every tool except [`NO_DEVICE_DATA_TOOLS`].
    fn assert_reached_fixture(tool: &str, result: &CallToolResult) {
        if NO_DEVICE_DATA_TOOLS.contains(&tool) {
            return;
        }
        assert_ne!(
            result.is_error,
            Some(true),
            "{tool} must succeed against the fixture to prove anything about redaction, \
             got an error result: {result:?}"
        );
        let rendered = format!("{result:?}");
        assert!(
            rendered.contains(FIXTURE_MARKER),
            "{tool} never reached the fixture (no {FIXTURE_MARKER:?} marker in the output), \
             so it proves nothing about redaction: {rendered}"
        );
    }

    /// MEC-699: every tool that can return device data must run its response
    /// through `mecmcp_redact` before the model ever sees it. This is a
    /// regression guard, not a design proof -- it iterates the server's own
    /// `KNOWN_TOOLS` registry (rather than a hand-maintained list) so a tool
    /// added later without redaction wiring fails this test instead of
    /// shipping quietly.
    ///
    /// One handler, one client, one caller for the whole sweep: transport or
    /// authorization failures are propagated as panics (via `.expect`), not
    /// swallowed as "no secret seen this call" passes -- a call that never
    /// reached the fixture proves nothing.
    #[tokio::test]
    async fn every_known_tool_redacts_fixture_secrets() {
        let handler = MistHandler::with_client_options(
            "https://api.mist.com/",
            vec![FIXTURE_ORG_ID.to_owned()],
            BTreeMap::from([(FIXTURE_SITE_ID.to_owned(), FIXTURE_ORG_ID.to_owned())]),
            Arc::new(SecretLeakClient {
                catalog: Arc::new(Catalog::embedded().expect("embedded catalog")),
            }),
            None,
            // Lab mode auto-waives approval at plan time, so this single
            // caller can drive the full plan -> approve -> apply lifecycle
            // without standing up the two-principal HTTP auth flow
            // `approver_gate.rs` covers separately.
            true,
        )
        .expect("handler");

        // MEC-1236 item 4 / MEC-1448: the fixture-leak assertions above only
        // ever looked at each call's rendered `CallToolResult`. A secret
        // could still reach the `tracing` output (plain log lines) or the
        // `audit` target (`mecmcp_audit::AuditScope`, which emits via
        // `tracing::info!(target: "audit", ...)` -- see
        // `mecmcp_audit::scope`) without either assertion ever seeing it.
        // Capturing here means every `sweep!` call below, and the
        // change-set lifecycle after it, has its log and audit output
        // checked too, not just its tool response.
        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());

        let mut covered = std::collections::BTreeSet::new();
        let ext = extensions(full_sweep_caller());

        macro_rules! sweep {
            ($tool:ident, $args:expr) => {{
                let name = stringify!($tool);
                covered.insert(name);
                let result = handler
                    .$tool(Parameters($args), ext.clone())
                    .await
                    .unwrap_or_else(|error| panic!("{name} transport error: {error}"));
                assert_no_secret_leak(name, &result);
                assert_reached_fixture(name, &result);
                result
            }};
        }

        sweep!(
            get_mist_self,
            serde_json::from_value::<EmptyArgs>(serde_json::json!({})).expect("args")
        );
        sweep!(
            get_mist_org,
            serde_json::from_value::<GetOrgArgs>(serde_json::json!({"org_id": FIXTURE_ORG_ID}))
                .expect("args")
        );
        sweep!(
            list_mist_sites,
            serde_json::from_value::<OrgPageArgs>(serde_json::json!({"org_id": FIXTURE_ORG_ID}))
                .expect("args")
        );
        sweep!(
            get_mist_site,
            serde_json::from_value::<SiteArgs>(serde_json::json!({"site_id": FIXTURE_SITE_ID}))
                .expect("args")
        );
        sweep!(
            search_mist_inventory,
            serde_json::from_value::<InventoryArgs>(serde_json::json!({"org_id": FIXTURE_ORG_ID}))
                .expect("args")
        );
        sweep!(
            get_mist_device,
            serde_json::from_value::<SiteDeviceArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID, "device_id": FIXTURE_DEVICE_ID})
            )
            .expect("args")
        );
        sweep!(
            get_mist_device_stats,
            serde_json::from_value::<DeviceStatsArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID, "device_id": FIXTURE_DEVICE_ID})
            )
            .expect("args")
        );
        sweep!(
            get_mist_insight,
            serde_json::from_value::<InsightArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID, "metrics": "num_clients"})
            )
            .expect("args")
        );
        sweep!(
            get_mist_operation_schema,
            serde_json::from_value::<OperationSchemaArgs>(
                serde_json::json!({"operation_id": "getOrg"})
            )
            .expect("args")
        );
        sweep!(
            get_mist_rrm,
            serde_json::from_value::<SiteArgs>(serde_json::json!({"site_id": FIXTURE_SITE_ID}))
                .expect("args")
        );
        sweep!(
            get_mist_sle,
            serde_json::from_value::<SleArgs>(serde_json::json!({
                "site_id": FIXTURE_SITE_ID, "scope": "site", "scope_id": FIXTURE_SITE_ID,
                "metric": "wan-link-health"
            }))
            .expect("args")
        );
        sweep!(
            get_mist_sle_impact,
            serde_json::from_value::<SleImpactArgs>(serde_json::json!({
                "site_id": FIXTURE_SITE_ID, "scope": "site", "scope_id": FIXTURE_SITE_ID,
                "metric": "wan-link-health", "impact": "summary"
            }))
            .expect("args")
        );
        sweep!(
            get_mist_wan_config,
            serde_json::from_value::<WanConfigGetArgs>(serde_json::json!({
                "object": "network", "org_id": FIXTURE_ORG_ID, "object_id": FIXTURE_NETWORK_ID
            }))
            .expect("args")
        );
        sweep!(
            get_mist_wan_edge_stats,
            serde_json::from_value::<WanEdgeStatsArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID})
            )
            .expect("args")
        );
        sweep!(
            invoke_mist_privileged_read,
            serde_json::from_value::<InvokeReadArgs>(
                serde_json::json!({"operation_id": "getSelf"})
            )
            .expect("args")
        );
        sweep!(
            invoke_mist_read,
            serde_json::from_value::<InvokeReadArgs>(serde_json::json!({
                "operation_id": "getOrg", "path": {"org_id": FIXTURE_ORG_ID}
            }))
            .expect("args")
        );
        sweep!(
            list_mist_alarm_definitions,
            serde_json::from_value::<EmptyArgs>(serde_json::json!({})).expect("args")
        );
        sweep!(
            list_mist_applications,
            serde_json::from_value::<ApplicationListArgs>(serde_json::json!({"source": "catalog"}))
                .expect("args")
        );
        {
            covered.insert("list_mist_orgs");
            let result = handler
                .list_mist_orgs(Parameters(EmptyArgs {}), ext.clone())
                .await
                .expect("list_mist_orgs transport error");
            assert_no_secret_leak("list_mist_orgs", &result);
            assert_reached_fixture("list_mist_orgs", &result);
        }
        sweep!(
            list_mist_rogues,
            serde_json::from_value::<RogueArgs>(serde_json::json!({"site_id": FIXTURE_SITE_ID}))
                .expect("args")
        );
        sweep!(
            list_mist_sle_metrics,
            serde_json::from_value::<SleMetricsArgs>(serde_json::json!({
                "site_id": FIXTURE_SITE_ID, "scope": "site", "scope_id": FIXTURE_SITE_ID
            }))
            .expect("args")
        );
        sweep!(
            list_mist_upgrades,
            serde_json::from_value::<UpgradeArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID, "status": null})
            )
            .expect("args")
        );
        sweep!(
            list_mist_wan_config,
            serde_json::from_value::<WanConfigListArgs>(serde_json::json!({
                "object": "network", "org_id": FIXTURE_ORG_ID
            }))
            .expect("args")
        );
        sweep!(
            list_mist_wan_edges,
            serde_json::from_value::<WanEdgeListArgs>(
                serde_json::json!({"org_id": FIXTURE_ORG_ID})
            )
            .expect("args")
        );
        sweep!(
            list_mist_wlans,
            serde_json::from_value::<SitePageArgs>(serde_json::json!({"site_id": FIXTURE_SITE_ID}))
                .expect("args")
        );
        sweep!(
            search_mist_alarms,
            serde_json::from_value::<AlarmSearchArgs>(
                serde_json::json!({"org_id": FIXTURE_ORG_ID})
            )
            .expect("args")
        );
        sweep!(
            search_mist_audit_logs,
            serde_json::from_value::<AuditSearchArgs>(
                serde_json::json!({"org_id": FIXTURE_ORG_ID})
            )
            .expect("args")
        );
        sweep!(
            search_mist_bgp_peers,
            serde_json::from_value::<BgpPeerSearchArgs>(
                serde_json::json!({"org_id": FIXTURE_ORG_ID})
            )
            .expect("args")
        );
        sweep!(
            search_mist_clients,
            serde_json::from_value::<ClientSearchArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID})
            )
            .expect("args")
        );
        sweep!(
            search_mist_events,
            serde_json::from_value::<EventSearchArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID})
            )
            .expect("args")
        );
        {
            covered.insert("search_mist_operations");
            let result = handler
                .search_mist_operations(
                    Parameters(
                        serde_json::from_value::<SearchOperationsArgs>(
                            serde_json::json!({"query": "org"}),
                        )
                        .expect("args"),
                    ),
                    ext.clone(),
                )
                .await
                .expect("search_mist_operations transport error");
            assert_no_secret_leak("search_mist_operations", &result);
            assert_reached_fixture("search_mist_operations", &result);
        }
        sweep!(
            search_mist_peer_paths,
            serde_json::from_value::<PeerPathSearchArgs>(
                serde_json::json!({"org_id": FIXTURE_ORG_ID})
            )
            .expect("args")
        );
        sweep!(
            search_mist_service_path_events,
            serde_json::from_value::<ServicePathEventArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID})
            )
            .expect("args")
        );
        sweep!(
            search_mist_tunnels,
            serde_json::from_value::<TunnelSearchArgs>(
                serde_json::json!({"org_id": FIXTURE_ORG_ID})
            )
            .expect("args")
        );
        sweep!(
            troubleshoot_mist,
            serde_json::from_value::<TroubleshootArgs>(
                serde_json::json!({"site_id": FIXTURE_SITE_ID})
            )
            .expect("args")
        );

        // The change-set lifecycle: `plan_mist_change` reads the fixture as
        // `before`, and `get_mist_change_set` re-reads the staged preview.
        // Both are the exact call sites `mecmcp_redact` was added to in this
        // change (`server/mod.rs` around `plan_mist_change`/
        // `get_mist_change_set`), so this is the sweep's most direct proof.
        let plan_result = sweep!(
            plan_mist_change,
            serde_json::from_value::<PlanChangeArgs>(serde_json::json!({
                "object": "network",
                "verb": "update",
                "org_id": FIXTURE_ORG_ID,
                "object_id": FIXTURE_NETWORK_ID,
                "patch": {"name": "renamed-branch"},
            }))
            .expect("args")
        );
        let plan_text = plan_result.content[0]
            .as_text()
            .expect("plan_mist_change returns text")
            .text
            .clone();
        let plan_json: serde_json::Value = serde_json::from_str(&plan_text).expect("plan JSON");
        let change_set_id = plan_json["change_set_id"]
            .as_str()
            .expect("change_set_id")
            .to_owned();
        let plan_digest = plan_json["plan_digest"]
            .as_str()
            .expect("plan_digest")
            .to_owned();

        sweep!(
            get_mist_change_set,
            serde_json::from_value::<GetChangeSetArgs>(serde_json::json!({
                "change_set_id": change_set_id, "object": "network", "object_id": FIXTURE_NETWORK_ID
            }))
            .expect("args")
        );
        sweep!(
            approve_mist_change_set,
            serde_json::from_value::<ApproveChangeSetArgs>(serde_json::json!({
                "change_set_id": change_set_id, "plan_digest": plan_digest,
                "object": "network", "object_id": FIXTURE_NETWORK_ID
            }))
            .expect("args")
        );
        {
            covered.insert("apply_mist_change_set");
            let result = handler
                .apply_mist_change_set(
                    Parameters(
                        serde_json::from_value::<ApplyChangeSetArgs>(serde_json::json!({
                            "change_set_id": change_set_id, "object": "network",
                            "object_id": FIXTURE_NETWORK_ID
                        }))
                        .expect("args"),
                    ),
                    ext.clone(),
                )
                .await
                .expect("apply_mist_change_set transport error");
            assert_no_secret_leak("apply_mist_change_set", &result);
            // Lab mode approved the plan on creation, so apply must succeed
            // here, not be refused -- the stale `NO_DEVICE_DATA_TOOLS` comment
            // previously claimed apply was "correctly refused", which was
            // never true under this sweep's lab-mode handler.
            assert_eq!(
                result.is_error,
                Some(false),
                "apply_mist_change_set must succeed in lab mode: {result:?}"
            );
        }

        // MEC-1236 item 4 / MEC-1448: the fixture secret must not have
        // reached logs or audit records for *any* tool exercised above,
        // mirroring `assert_no_secret_leak`'s per-tool check but against
        // everything captured for the whole sweep.
        let logged = String::from_utf8(capture.0.lock().expect("capture").clone())
            .expect("captured log/audit output is UTF-8");
        for (name, secret) in FIXTURE_SECRETS {
            assert!(
                !logged.contains(secret),
                "fixture secret {name} leaked into logs or audit records during the sweep"
            );
        }

        let expected: std::collections::BTreeSet<&str> = KNOWN_TOOLS.iter().copied().collect();
        assert_eq!(
            covered, expected,
            "every tool in KNOWN_TOOLS must be swept for fixture-secret leakage; \
             a tool present in one set but not the other means this test was not \
             updated alongside the registry"
        );
    }

    /// Negative control for the log/audit capture added above: proves the
    /// capture mechanism itself would catch a leaked secret, rather than
    /// passing merely because nothing was ever planted in the log stream.
    /// Without this, a regression that silently broke `install_audit_capture`
    /// (wrong target, wrong level, wrong thread) would make
    /// `every_known_tool_redacts_fixture_secrets` pass for the wrong reason.
    #[tokio::test]
    async fn planted_log_secret_is_caught_by_the_capture_harness() {
        const PLANTED_SECRET: &str = "FAKE-PLANTED-LOG-SECRET-7a8b9c0d";

        let capture = CapturingWriter::default();
        let _capture_guard = install_audit_capture(capture.clone());

        tracing::info!(target: "audit", secret = PLANTED_SECRET, "planted for negative control");

        let logged = String::from_utf8(capture.0.lock().expect("capture").clone())
            .expect("captured log/audit output is UTF-8");
        assert!(
            logged.contains(PLANTED_SECRET),
            "capture harness did not observe a secret logged on its own thread; \
             the assertions in every_known_tool_redacts_fixture_secrets would \
             pass vacuously if this broke"
        );
    }

    /// `--approval-timeout-secs` must not be silently ignored: `load_coordinator`
    /// must use the timeout it is given rather than a hardcoded default.
    #[tokio::test]
    async fn an_approval_timeout_passed_to_load_coordinator_is_honored() {
        let non_default = std::time::Duration::from_secs(120);
        assert_ne!(non_default, DEFAULT_APPROVAL_TIMEOUT);

        let coordinator = load_coordinator(None, false, None, None, non_default)
            .expect("coordinator with a configured approval timeout");

        assert_eq!(
            coordinator.approval_ttl(),
            non_default,
            "load_coordinator must use the timeout passed to it, not a hardcoded default"
        );
    }

    /// A security-relevant configuration flag must not be silently ignored:
    /// a coordinator built with a key via `load_coordinator` has to actually
    /// produce the stronger, keyed approval digest, not the weaker default
    /// one an operator who thinks the flag protects them would otherwise get.
    #[tokio::test]
    async fn an_approval_digest_key_passed_to_load_coordinator_produces_a_v6_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("changeset-state.json");
        let key = b"a-sufficiently-long-test-key".as_slice();

        let coordinator = load_coordinator(
            Some(&state_path),
            false,
            None,
            Some(mecmcp_changeset::ApprovalDigestKey::new(key)),
            DEFAULT_APPROVAL_TIMEOUT,
        )
        .expect("coordinator with a configured key");

        let created = coordinator
            .create_change_set(
                "site/device-a".to_string(),
                vec![serde_json::json!({"action": "set", "target": "/test"})],
                "alice".to_string(),
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                "policy-sig".to_string(),
            )
            .await
            .expect("create");
        coordinator
            .approve_change_set(
                created.change_set_id.clone(),
                "site/device-a".to_string(),
                "bob".to_string(),
                created.digest.clone(),
                mecmcp_audit::ActorType::Human,
            )
            .await
            .expect("approve");

        let state = mecmcp_changeset::persistence::read_state_with_key(
            &state_path,
            change_set_limits().max_state_bytes,
            Some(key),
        )
        .expect("read back with the same key");
        let approval = state.change_sets[&created.change_set_id]
            .approval
            .as_ref()
            .expect("approval");
        assert_eq!(
            approval.digest_version, 6,
            "a key passed through load_coordinator must actually take effect and produce \
             the stronger, keyed digest -- otherwise configuring it does nothing"
        );

        drop(coordinator);
        let unkeyed_read = mecmcp_changeset::persistence::read_state_with_key(
            &state_path,
            change_set_limits().max_state_bytes,
            None,
        );
        assert!(
            unkeyed_read.is_err(),
            "a v6 digest produced through load_coordinator must not verify without the key"
        );
    }
}

#[cfg(test)]
mod tools_list_cache_tests {
    use super::listed_tools;

    /// A 2026-07-28 client rejects a tools/list without these, and the failure
    /// reads as an unreachable server rather than a malformed reply.
    #[test]
    fn a_modern_client_gets_a_private_cache_descriptor() {
        let listed = listed_tools(Vec::new(), true);
        assert_eq!(
            listed.ttl_ms,
            Some(0),
            "a 2026-07-28 client rejects a tools/list without ttlMs"
        );
        assert_eq!(
            listed.cache_scope,
            Some(rmcp::model::CacheScope::Private),
            "the list is filtered per token, so it must not be shared"
        );
    }

    /// The fields are not part of the older result shape, and a strict legacy
    /// client rejects what it did not negotiate.
    #[test]
    fn a_legacy_client_gets_no_cache_descriptor() {
        let listed = listed_tools(Vec::new(), false);
        assert_eq!(listed.ttl_ms, None);
        assert_eq!(listed.cache_scope, None);
    }
}
