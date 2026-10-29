//! Command-line arguments for the Mist MCP server.

use clap::Parser;
use rustmistmcp_core::HttpMistClientConfig;
use std::path::PathBuf;
use std::time::Duration;

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
    /// Works on any bind address. Callers off loopback still need bearer
    /// tokens, and a startup WARN is logged. A loopback bind reachable through
    /// a reverse proxy or an SSH/port forward is still reachable by remote
    /// callers; keeping this server unreachable from outside the host is the
    /// operator's job.
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

    /// TCP connect timeout, in seconds, for outbound Mist API requests.
    #[arg(
        long = "mist-connect-timeout-secs",
        env = "MIST_CONNECT_TIMEOUT_SECS",
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..=300)
    )]
    pub mist_connect_timeout_secs: u64,

    /// Total timeout, in seconds, for one outbound Mist API request.
    #[arg(
        long = "mist-request-timeout-secs",
        env = "MIST_REQUEST_TIMEOUT_SECS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=600)
    )]
    pub mist_request_timeout_secs: u64,

    /// Maximum retries after an HTTP 429 from Mist; `0` disables retrying.
    #[arg(
        long = "mist-max-429-retries",
        env = "MIST_MAX_429_RETRIES",
        default_value_t = 2,
        value_parser = clap::value_parser!(u8).range(0..=5)
    )]
    pub mist_max_429_retries: u8,

    /// Ceiling, in seconds, on a single 429 retry wait (`Retry-After` or backoff).
    #[arg(
        long = "mist-max-retry-wait-secs",
        env = "MIST_MAX_RETRY_WAIT_SECS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=120)
    )]
    pub mist_max_retry_wait_secs: u64,
}

impl MistCli {
    /// Build the production Mist HTTP client config from the `--mist-*` flags.
    ///
    /// Every field the flags do not cover keeps its
    /// [`HttpMistClientConfig::default`] value.
    pub fn mist_client_config(&self) -> HttpMistClientConfig {
        HttpMistClientConfig {
            connect_timeout: Duration::from_secs(self.mist_connect_timeout_secs),
            request_timeout: Duration::from_secs(self.mist_request_timeout_secs),
            max_429_retries: self.mist_max_429_retries,
            max_retry_wait: Duration::from_secs(self.mist_max_retry_wait_secs),
            ..HttpMistClientConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> Result<MistCli, clap::Error> {
        let mut argv = vec!["rustmistmcp", "--device-mapping", "/dev/null"];
        argv.extend_from_slice(extra);
        MistCli::try_parse_from(argv)
    }

    #[test]
    fn defaults_equal_client_config_default() {
        let config = parse(&[]).expect("defaults parse").mist_client_config();
        let default = HttpMistClientConfig::default();
        assert_eq!(config.connect_timeout, default.connect_timeout);
        assert_eq!(config.request_timeout, default.request_timeout);
        assert_eq!(config.max_429_retries, default.max_429_retries);
        assert_eq!(config.max_retry_wait, default.max_retry_wait);
    }

    #[test]
    fn flags_map_to_matching_config_fields() {
        let config = parse(&[
            "--mist-connect-timeout-secs",
            "3",
            "--mist-request-timeout-secs",
            "7",
            "--mist-max-429-retries",
            "5",
            "--mist-max-retry-wait-secs",
            "11",
        ])
        .expect("overrides parse")
        .mist_client_config();
        assert_eq!(config.connect_timeout, Duration::from_secs(3));
        assert_eq!(config.request_timeout, Duration::from_secs(7));
        assert_eq!(config.max_429_retries, 5);
        assert_eq!(config.max_retry_wait, Duration::from_secs(11));
        let default = HttpMistClientConfig::default();
        assert_eq!(config.max_response_bytes, default.max_response_bytes);
        assert_eq!(config.max_concurrency, default.max_concurrency);
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        for bad in [
            ["--mist-connect-timeout-secs", "0"],
            ["--mist-connect-timeout-secs", "301"],
            ["--mist-request-timeout-secs", "0"],
            ["--mist-request-timeout-secs", "601"],
            ["--mist-max-429-retries", "6"],
            ["--mist-max-retry-wait-secs", "0"],
            ["--mist-max-retry-wait-secs", "121"],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(parse(&["--mist-max-429-retries", "0"]).is_ok());
    }
}
