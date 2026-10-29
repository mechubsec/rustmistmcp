//! Command-line arguments for the Mist MCP server.

use clap::Parser;
use std::path::PathBuf;

// Re-export from mecmcp-runtime for compatibility
pub use mecmcp_runtime::cli::{Command, Transport, WebApproverArgs};

#[derive(Debug, Parser)]
#[command(name = "rustmistmcp", version, about = "HPE Juniper Mist MCP server")]
pub struct MistCli {
    /// Flatten the shared CLI so every flag behaves identically across the fleet.
    #[command(flatten)]
    pub shared: mecmcp_runtime::cli::Cli,

    /// Change-set lifecycle state file for two-person approval workflow.
    #[arg(
        long = "state-file",
        default_value = "/var/lib/rustmistmcp/changeset-state.json"
    )]
    pub state_file: PathBuf,

    /// Change-set approval timeout in seconds.
    #[arg(long = "approval-timeout-secs", default_value_t = 3600)]
    pub approval_timeout_secs: u64,

    /// Run without two-person control: change sets are approved on creation.
    ///
    /// For single-operator environments — a lab with one engineer — where
    /// requiring a second principal makes change sets unusable rather than
    /// safer.
    ///
    /// No approver is invented. A waived change set records `approver: null`
    /// with `waived: { reason: "lab-mode" }`, so it stays distinguishable from one
    /// a second person actually reviewed.
    ///
    /// Refused at startup unless the listener binds loopback -- but a loopback
    /// bind reachable through a reverse proxy or an SSH/port forward is still
    /// reachable by remote callers, and this check cannot see that. Keeping
    /// this server unreachable from outside the host is the operator's job.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Web approver settings (--web-enabled-approver).
    #[command(flatten)]
    pub web_approver: WebApproverArgs,

    /// Seconds between background refreshes of the org → site map used to
    /// authorize site-scoped tool calls. `0` discovers once at startup and
    /// never refreshes, so newly added or removed sites require a restart.
    #[arg(long = "site-refresh-interval-secs", default_value_t = 300)]
    pub site_refresh_interval_secs: u64,

    /// `--tool-mode full|compact` (env `MCP_TOOL_MODE`): compact lists only the
    /// four catalog dispatchers. Listing only; token scopes still authorize.
    #[command(flatten)]
    pub tool_mode: mecmcp_runtime::cli::ToolModeArgs,
}
