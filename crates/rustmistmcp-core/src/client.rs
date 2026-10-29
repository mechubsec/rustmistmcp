//! Injectable Mist dispatch contract.

use async_trait::async_trait;
use mecmcp_secret::OutboundSecret;
use std::sync::Arc;
use tokio::sync::Semaphore;
use url::Url;

use crate::catalog::PaginationMode;
use crate::rate_limit::{BudgetStatus, CallPriority, RateLimitBudget};
use crate::{Catalog, MistCursor, MistPageInfo, MistRequest, MistResponse, MistResponseBody};

/// An injected, asynchronous dispatcher for already-validated Mist requests.
///
/// Implementations are supplied by the application. This crate does not make
/// network requests, load credentials, or retry operations at this boundary.
#[async_trait]
pub trait MistClient: Send + Sync {
    /// Execute one catalog-bound request, as [`CallPriority::Standard`].
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        self.execute_as(request, CallPriority::Standard).await
    }

    /// Execute one catalog-bound request under an explicit budget priority.
    ///
    /// Callers should pass [`CallPriority::Reserved`] only for a call a
    /// server has verified is human-initiated (`mecmcp_auth::ActorType::Human`).
    /// The default implementation ignores `priority` and delegates to
    /// [`MistClient::execute`], for clients that do not track a budget.
    async fn execute_as(
        &self,
        request: MistRequest,
        _priority: CallPriority,
    ) -> Result<MistResponse, MistError> {
        self.execute(request).await
    }

    /// This token's current hourly call budget headroom, if this client tracks one.
    fn budget_status(&self) -> Option<BudgetStatus> {
        None
    }

    /// Whether this transport refuses everything without touching the network.
    ///
    /// Exists so the production constructor's choice of client is assertable
    /// without a live tenant. The endpoint allowlist only admits real Mist
    /// regions, so "point it at an unreachable host and inspect the error" is
    /// not available, and a test that builds its own client cannot see the
    /// wiring at all — which is how `from_config` shipped returning the stub.
    fn is_blocked(&self) -> bool {
        false
    }
}

/// Deliberately unavailable client used where no Mist transport should exist.
///
/// It was the default while `mecmcp#90` was open. That foundation has landed
/// and `MistHandler::from_config` now builds a real `HttpMistClient`, so this
/// remains only for tests and for handlers constructed without a credential:
/// it performs no I/O and never loads one.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedMistClient;

#[async_trait]
impl MistClient for BlockedMistClient {
    fn is_blocked(&self) -> bool {
        true
    }

    async fn execute(&self, _request: MistRequest) -> Result<MistResponse, MistError> {
        Err(MistError::TransportUnavailable)
    }
}

/// Stable errors exchanged across the Mist dispatch seam.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MistError {
    /// The requested operation is not present in the audited catalog.
    #[error("unknown Mist operation: {0}")]
    UnknownOperation(String),
    /// A value conflicts with the selected operation's catalog contract.
    #[error("invalid Mist request for {operation_id}: {reason}")]
    InvalidRequest {
        /// The supplied operation ID.
        operation_id: String,
        /// A human-readable validation reason; schema-validator text is not a
        /// compatibility promise.
        reason: String,
    },
    /// A supplied response conflicts with the selected operation's catalog contract.
    #[error("invalid Mist response for {operation_id}: {reason}")]
    InvalidResponse {
        /// The supplied operation ID.
        operation_id: String,
        /// A human-readable validation reason.
        reason: String,
    },
    /// A continuation cursor is malformed or does not match its request.
    #[error("invalid Mist cursor: {0}")]
    InvalidCursor(String),
    /// A supplied client already parsed a Mist rate-limit result.
    #[error("Mist API rate-limited the request")]
    RateLimited {
        /// Parsed `Retry-After` seconds, when the shared transport supplied it.
        retry_after_secs: Option<u64>,
    },
    /// No production transport exists at this open-prerequisite seam.
    #[error("Mist client transport is unavailable")]
    TransportUnavailable,
    /// The Mist API answered 410 Gone: the vendor has retired this endpoint.
    #[error(
        "Mist API operation {operation_id} has been retired by the vendor (HTTP 410); \
         it needs a replacement operation, not a retry"
    )]
    EndpointRetired {
        /// The operation that the vendor retired.
        operation_id: String,
    },
    /// A supplied client mapped a Mist service failure.
    #[error("Mist API request failed: {0}")]
    Service(String),
    /// This token's local hourly call budget is exhausted for the request's priority.
    ///
    /// Raised before any network call is made, so it never consumes a real
    /// Mist API call. Distinct from [`MistError::RateLimited`], which reflects
    /// Mist's own HTTP 429 response.
    #[error(
        "Mist hourly call budget exhausted: used {used}/{hourly_limit} ({human_reserve} reserved for human operators)"
    )]
    BudgetExhausted {
        /// Calls already counted against this hourly window.
        used: u32,
        /// The configured hourly call ceiling for this token.
        hourly_limit: u32,
        /// The portion of `hourly_limit` reserved for human operators.
        human_reserve: u32,
    },
}

/// Production HTTPS Mist client over mecmcp-http.
#[derive(Clone)]
pub struct HttpMistClient {
    http: Arc<mecmcp_http::HttpClient>,
    base_url: Url,
    credential: Arc<OutboundSecret>,
    catalog: Arc<Catalog>,
    concurrency: Arc<Semaphore>,
    budget: Arc<RateLimitBudget>,
    max_429_retries: u8,
    max_retry_wait: std::time::Duration,
}

impl std::fmt::Debug for HttpMistClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpMistClient")
            .field("base_url", &self.base_url)
            .field("credential", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl HttpMistClient {
    /// Build a production HTTPS-only client.
    ///
    /// The consuming binary must install a rustls crypto provider first.
    ///
    /// # Errors
    ///
    /// Returns configuration or client-construction errors.
    pub fn new(
        endpoint: &str,
        credential: String,
        catalog: Arc<Catalog>,
        config: HttpMistClientConfig,
    ) -> Result<Self, HttpMistClientError> {
        let base_url = Url::parse(endpoint).map_err(|_| HttpMistClientError::InvalidEndpoint)?;

        if base_url.scheme() != "https" {
            return Err(HttpMistClientError::InvalidEndpoint);
        }

        if credential.is_empty() || credential.len() > 16 * 1024 {
            return Err(HttpMistClientError::InvalidCredential);
        }

        let http_config = mecmcp_http::HttpClientConfig {
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
            max_concurrent_requests: config.max_concurrency,
            max_queued_requests: config.max_concurrency * 2,
            pool_idle_timeout: std::time::Duration::from_secs(300),
            pool_max_idle_per_host: config.max_concurrency,
            user_agent: format!("rustmistmcp/{}", env!("CARGO_PKG_VERSION")),
            max_response_bytes: config.max_response_bytes,
            extra_root_certificates: vec![],
        };

        let http = mecmcp_http::HttpClient::new(http_config)
            .map_err(|_| HttpMistClientError::ClientConstruction)?;

        Ok(Self {
            http: Arc::new(http),
            base_url,
            credential: Arc::new(OutboundSecret::new_unchecked(credential)),
            catalog,
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
            budget: Arc::new(RateLimitBudget::new(
                config.hourly_call_budget,
                config.human_reserve,
            )),
            max_429_retries: config.max_429_retries,
            max_retry_wait: config.max_retry_wait,
        })
    }

    /// Construct an [`HttpMistClient`] from explicit parts for integration tests.
    ///
    /// Bypasses endpoint validation and HTTPS enforcement, allowing tests to use
    /// plain HTTP mock servers. Do not use in production code.
    ///
    /// Gated behind `test-util` rather than compiled unconditionally: this was
    /// `pub` with no gate at all, so every normal build -- including a release
    /// binary -- shipped a constructor that skips both checks
    /// [`HttpMistClient::new`] enforces. A consumer's integration tests enable
    /// the feature in their own `[dev-dependencies]` entry for this crate.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_test_parts(
        base_url: Url,
        credential: String,
        catalog: Arc<Catalog>,
        max_response_bytes: usize,
    ) -> Self {
        Self::from_test_parts_with_config(
            base_url,
            credential,
            catalog,
            HttpMistClientConfig {
                connect_timeout: std::time::Duration::from_secs(1),
                request_timeout: std::time::Duration::from_secs(2),
                max_response_bytes,
                max_concurrency: 2,
                ..HttpMistClientConfig::default()
            },
            vec![],
        )
    }

    /// As [`Self::from_test_parts`], additionally trusting `extra_root_certificates`.
    ///
    /// `mecmcp-http` refuses any outbound scheme but `https`, so a mock server
    /// that proves real wire behavior needs a certificate the client is told to
    /// trust. Each certificate is PEM-encoded. Thin wrapper over
    /// [`Self::from_test_parts_with_config`].
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_test_parts_with_roots(
        base_url: Url,
        credential: String,
        catalog: Arc<Catalog>,
        max_response_bytes: usize,
        extra_root_certificates: Vec<String>,
    ) -> Self {
        Self::from_test_parts_with_config(
            base_url,
            credential,
            catalog,
            HttpMistClientConfig {
                connect_timeout: std::time::Duration::from_secs(1),
                request_timeout: std::time::Duration::from_secs(2),
                max_response_bytes,
                max_concurrency: 2,
                ..HttpMistClientConfig::default()
            },
            extra_root_certificates,
        )
    }

    /// As [`HttpMistClient::from_test_parts`], but with full control over
    /// [`HttpMistClientConfig`] and any extra trusted root certificates --
    /// needed by tests that exercise the budget tracker or the bounded
    /// 429-retry loop against a self-signed TLS mock.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_test_parts_with_config(
        base_url: Url,
        credential: String,
        catalog: Arc<Catalog>,
        config: HttpMistClientConfig,
        trusted_root_pem: Vec<String>,
    ) -> Self {
        let http_config = mecmcp_http::HttpClientConfig {
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
            max_concurrent_requests: config.max_concurrency,
            max_queued_requests: config.max_concurrency * 2,
            pool_idle_timeout: std::time::Duration::from_secs(60),
            pool_max_idle_per_host: config.max_concurrency,
            user_agent: "rustmistmcp-test".to_owned(),
            max_response_bytes: config.max_response_bytes,
            extra_root_certificates: trusted_root_pem,
        };

        let http = mecmcp_http::HttpClient::new(http_config).expect("test client");

        Self {
            http: Arc::new(http),
            base_url,
            credential: Arc::new(OutboundSecret::new_unchecked(credential)),
            catalog,
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
            budget: Arc::new(RateLimitBudget::new(
                config.hourly_call_budget,
                config.human_reserve,
            )),
            max_429_retries: config.max_429_retries,
            max_retry_wait: config.max_retry_wait,
        }
    }

    /// The query parameter Mist expects a continuation value written back to,
    /// keyed by the pagination shape declared in the catalog.
    fn cursor_query_key(mode: PaginationMode) -> Option<&'static str> {
        match mode {
            PaginationMode::SearchAfter => Some("search_after"),
            PaginationMode::PageLimit => Some("page"),
            PaginationMode::None => None,
        }
    }

    fn build_url(
        &self,
        operation_id: &str,
        path: &std::collections::BTreeMap<String, String>,
        query: &std::collections::BTreeMap<String, serde_json::Value>,
        cursor: Option<&MistCursor>,
    ) -> Result<Url, MistError> {
        let operation = self
            .catalog
            .operation(operation_id)
            .ok_or_else(|| MistError::UnknownOperation(operation_id.to_owned()))?;

        let mut url = self.base_url.clone();
        // Each value is percent-encoded into exactly one segment; values that
        // would add a segment, a query, or `..` are refused, as are unknown
        // parameters and unfilled placeholders.
        let params: Vec<(&str, &str)> = path
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let expanded_path =
            mecmcp_openapi::expand_path(&operation.path, &params).map_err(|error| {
                MistError::InvalidRequest {
                    operation_id: operation_id.to_owned(),
                    reason: error.to_string(),
                }
            })?;

        url.set_path(expanded_path.as_str());

        // A continuation replaces whatever page/search_after value the stored
        // request context carried forward, so it is merged into the query map
        // before encoding rather than appended: appending would send both the
        // stale and the fresh value as duplicate query parameters.
        let mut effective_query = query.clone();
        if let Some(cursor) = cursor {
            let key = Self::cursor_query_key(cursor.mode()).ok_or_else(|| {
                MistError::InvalidCursor("cursor pagination mode must not be none".to_owned())
            })?;
            effective_query.insert(
                key.to_owned(),
                serde_json::Value::String(cursor.value().to_owned()),
            );
        }

        // Add query parameters
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in &effective_query {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Null => continue,
                    _ => {
                        return Err(MistError::InvalidRequest {
                            operation_id: operation_id.to_owned(),
                            reason: format!(
                                "query parameter {key} must be string, number, or bool"
                            ),
                        });
                    }
                };
                pairs.append_pair(key, &value_str);
            }
        }

        Ok(url)
    }

    /// Parse the `X-Page-Page`, `X-Page-Limit`, and `X-Page-Total` response
    /// headers Mist's `page`/`limit` endpoints use to report pagination state.
    ///
    /// Those endpoints return a bare JSON array as the body (see
    /// `listOrgSites`), so the headers are the only place this state appears.
    fn parse_page_info(response: &mecmcp_http::HttpResponse) -> Option<MistPageInfo> {
        let info = MistPageInfo {
            page: response
                .header_str("X-Page-Page")
                .and_then(|value| value.parse().ok()),
            limit: response
                .header_str("X-Page-Limit")
                .and_then(|value| value.parse().ok()),
            total: response
                .header_str("X-Page-Total")
                .and_then(|value| value.parse().ok()),
        };
        if info.is_empty() { None } else { Some(info) }
    }

    /// Extract the `search_after` value Mist embeds in the `next` URL of a
    /// search-style response body.
    ///
    /// Mist's search-after endpoints (for example `searchOrgAlarms`) do not
    /// return the continuation value as its own body field; they return a
    /// `next` field holding a full (or origin-relative) URL for the next page,
    /// and the `search_after` query parameter inside that URL is the only part
    /// of it that changes between pages.
    fn extract_search_after_cursor(
        &self,
        json: &serde_json::Value,
        operation_id: &str,
    ) -> Option<MistCursor> {
        let next = json.get("next")?.as_str()?;
        if next.is_empty() {
            return None;
        }
        let next_url = self.base_url.join(next).ok()?;
        let search_after = next_url
            .query_pairs()
            .find(|(key, _)| key == "search_after")?
            .1
            .into_owned();
        if search_after.is_empty() {
            return None;
        }
        MistCursor::new(
            operation_id.to_owned(),
            &self.base_url,
            PaginationMode::SearchAfter,
            search_after,
        )
        .ok()
    }

    /// Derive the continuation cursor for a response, per the operation's
    /// declared pagination shape.
    fn derive_next_cursor(
        &self,
        operation_id: &str,
        body: &MistResponseBody,
        page: Option<&MistPageInfo>,
    ) -> Option<MistCursor> {
        let operation = self.catalog.operation(operation_id)?;
        match operation.pagination {
            PaginationMode::None => None,
            PaginationMode::SearchAfter => {
                let MistResponseBody::Json(json) = body else {
                    return None;
                };
                self.extract_search_after_cursor(json, operation_id)
            }
            PaginationMode::PageLimit => {
                let page = page?;
                let (current_page, limit, total) = (page.page?, page.limit?, page.total?);
                if limit == 0 || current_page.saturating_mul(limit) >= total {
                    return None;
                }
                MistCursor::new(
                    operation_id.to_owned(),
                    &self.base_url,
                    PaginationMode::PageLimit,
                    current_page.checked_add(1)?.to_string(),
                )
                .ok()
            }
        }
    }
}

#[async_trait]
impl MistClient for HttpMistClient {
    async fn execute_as(
        &self,
        request: MistRequest,
        priority: CallPriority,
    ) -> Result<MistResponse, MistError> {
        let _permit = self.concurrency.acquire().await.expect("semaphore");

        // Charged once per logical call: bounded 429 retries below reuse this
        // reservation rather than drawing the budget down further, since they
        // are this crate's own backoff for one Mist-side request, not
        // independent calls a caller asked for.
        self.budget.try_acquire(priority).map_err(|_| {
            let status = self.budget.status();
            MistError::BudgetExhausted {
                used: status.used,
                hourly_limit: status.hourly_limit,
                human_reserve: status.human_reserve,
            }
        })?;

        let url = self.build_url(
            &request.operation_id,
            &request.path,
            &request.query,
            request.cursor.as_ref(),
        )?;

        let operation = self
            .catalog
            .operation(&request.operation_id)
            .ok_or_else(|| MistError::UnknownOperation(request.operation_id.clone()))?;

        let method = match operation.method.as_str() {
            "GET" => mecmcp_http::Method::Get,
            "POST" => mecmcp_http::Method::Post,
            "PUT" => mecmcp_http::Method::Put,
            "PATCH" => mecmcp_http::Method::Patch,
            "DELETE" => mecmcp_http::Method::Delete,
            other => {
                return Err(MistError::InvalidRequest {
                    operation_id: request.operation_id.clone(),
                    reason: format!("unsupported HTTP method: {other}"),
                });
            }
        };

        let auth_secret =
            OutboundSecret::new_unchecked(format!("Token {}", self.credential.expose()));
        let body_bytes =
            match &request.json {
                Some(json_body) => Some(serde_json::to_vec(json_body).map_err(|_| {
                    MistError::Service("failed to serialize request body".to_owned())
                })?),
                None => None,
            };

        let mut retries_used: u8 = 0;
        let http_response = loop {
            // `with_base_and_path` cannot express this request: Mist operations
            // carry query parameters (pagination, filters) and mecmcp-http 0.25
            // has no way to attach a query to a path-templated request. `url` is
            // already assembled and validated by `build_url` above from the
            // catalog's path template, so this is the same shape `HttpRequest::new`
            // took pre-MEC-510, not a new bypass.
            let mut http_request =
                mecmcp_http::HttpRequest::from_absolute_url(method, url.as_str())
                    .map_err(|_| MistError::Service("failed to build HTTP request".to_owned()))?;
            http_request = http_request
                .secret_header("Authorization", &auth_secret)
                .map_err(|_| MistError::Service("failed to set auth header".to_owned()))?;
            if let Some(body_bytes) = &body_bytes {
                http_request = http_request.body(body_bytes.clone());
            }

            let response = self
                .http
                .send(http_request)
                .await
                .map_err(|error| MistError::Service(format!("HTTP request failed: {error}")))?;

            if response.status() != 429 {
                break response;
            }

            let header_retry_after = response
                .header_str("Retry-After")
                .and_then(|value| value.parse::<u64>().ok());

            if retries_used >= self.max_429_retries {
                return Err(MistError::RateLimited {
                    retry_after_secs: header_retry_after,
                });
            }

            let backoff = std::time::Duration::from_millis(200 * 2u64.pow(u32::from(retries_used)));
            let wait = header_retry_after
                .map(std::time::Duration::from_secs)
                .unwrap_or(backoff)
                .min(self.max_retry_wait);
            retries_used += 1;
            tokio::time::sleep(wait).await;
        };

        let status = http_response.status();

        // The vendor retires endpoints outright rather than deprecating them
        // in place; a 410 is a permanent, non-retryable signal that this
        // operation needs a replacement, not a generic HTTP failure.
        if status == 410 {
            return Err(MistError::EndpointRetired {
                operation_id: request.operation_id,
            });
        }

        // Get response body
        let body_bytes = http_response.body().to_vec();
        let body = if body_bytes.is_empty() {
            MistResponseBody::Empty
        } else {
            match serde_json::from_slice(&body_bytes) {
                Ok(json) => MistResponseBody::Json(json),
                Err(_) => match String::from_utf8(body_bytes.clone()) {
                    Ok(text) => MistResponseBody::Text(text),
                    Err(_) => MistResponseBody::Binary(body_bytes),
                },
            }
        };

        let page = Self::parse_page_info(&http_response);
        let cursor = self.derive_next_cursor(&request.operation_id, &body, page.as_ref());

        Ok(MistResponse {
            operation_id: request.operation_id,
            status,
            body,
            cursor,
            page,
        })
    }

    fn budget_status(&self) -> Option<BudgetStatus> {
        Some(self.budget.status())
    }
}

/// Configuration for the HTTP Mist client.
#[derive(Clone, Debug)]
pub struct HttpMistClientConfig {
    /// TCP connect timeout.
    pub connect_timeout: std::time::Duration,
    /// Whole-request deadline.
    pub request_timeout: std::time::Duration,
    /// Maximum response body bytes.
    pub max_response_bytes: usize,
    /// Maximum concurrent requests.
    pub max_concurrency: usize,
    /// This token's hourly Mist API call ceiling.
    ///
    /// Mist's documented default is 5,000 calls/hour per token.
    pub hourly_call_budget: u32,
    /// The portion of `hourly_call_budget` reserved for
    /// [`CallPriority::Reserved`] (human-initiated) calls.
    pub human_reserve: u32,
    /// Additional attempts made after Mist returns HTTP 429, before giving up.
    ///
    /// `0` means the first 429 response is returned to the caller without
    /// retrying; retries never run unbounded.
    pub max_429_retries: u8,
    /// Ceiling on how long a single 429 retry waits, whether that wait comes
    /// from a `Retry-After` header or the built-in backoff.
    ///
    /// Bounds a hostile or misconfigured `Retry-After` value from stalling a
    /// caller indefinitely.
    pub max_retry_wait: std::time::Duration,
}

impl Default for HttpMistClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: std::time::Duration::from_secs(10),
            request_timeout: std::time::Duration::from_secs(30),
            max_response_bytes: 10 * 1024 * 1024,
            max_concurrency: 8,
            hourly_call_budget: 5_000,
            human_reserve: 250,
            max_429_retries: 2,
            max_retry_wait: std::time::Duration::from_secs(30),
        }
    }
}

/// Errors from HTTP client construction.
#[derive(Debug, thiserror::Error)]
pub enum HttpMistClientError {
    /// The endpoint URL is invalid or not HTTPS.
    #[error("invalid Mist endpoint URL")]
    InvalidEndpoint,
    /// The credential is empty or too large.
    #[error("invalid Mist credential")]
    InvalidCredential,
    /// Failed to construct the HTTP client.
    #[error("failed to construct HTTP client")]
    ClientConstruction,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const TEST_TOKEN: &str = "test-token-12345";
    const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";

    fn test_catalog() -> Arc<Catalog> {
        Arc::new(Catalog::embedded().expect("embedded catalog"))
    }

    #[test]
    fn http_client_construction_validates_endpoint() {
        let catalog = test_catalog();

        // HTTP URLs are rejected
        let http_result = HttpMistClient::new(
            "http://api.mist.com/",
            TEST_TOKEN.to_owned(),
            catalog.clone(),
            HttpMistClientConfig::default(),
        );
        assert!(matches!(
            http_result,
            Err(HttpMistClientError::InvalidEndpoint)
        ));

        // HTTPS URLs are accepted
        let https_result = HttpMistClient::new(
            "https://api.mist.com/",
            TEST_TOKEN.to_owned(),
            catalog,
            HttpMistClientConfig::default(),
        );
        assert!(https_result.is_ok());
    }

    #[test]
    fn http_client_rejects_invalid_credentials() {
        let catalog = test_catalog();

        // Empty credential
        let empty_result = HttpMistClient::new(
            "https://api.mist.com/",
            String::new(),
            catalog.clone(),
            HttpMistClientConfig::default(),
        );
        assert!(matches!(
            empty_result,
            Err(HttpMistClientError::InvalidCredential)
        ));

        // Oversized credential (> 16KB)
        let large_cred = "x".repeat(17 * 1024);
        let large_result = HttpMistClient::new(
            "https://api.mist.com/",
            large_cred,
            catalog,
            HttpMistClientConfig::default(),
        );
        assert!(matches!(
            large_result,
            Err(HttpMistClientError::InvalidCredential)
        ));
    }

    #[test]
    fn http_client_builds_correct_url_with_path_parameters() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
        let query = BTreeMap::new();

        let url = client
            .build_url("getOrg", &path, &query, None)
            .expect("build URL");
        assert_eq!(url.path(), format!("/api/v1/orgs/{ORG_ID}"));
    }

    fn build_url_for_org_id(org_id: &str) -> Result<Url, MistError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );
        let path = BTreeMap::from([("org_id".to_owned(), org_id.to_owned())]);
        client.build_url("getOrg", &path, &BTreeMap::new(), None)
    }

    #[test]
    fn build_url_percent_encodes_path_values_without_double_encoding() {
        let url = build_url_for_org_id("a b").expect("space");
        assert_eq!(url.path(), "/api/v1/orgs/a%20b");
        let url = build_url_for_org_id("caf\u{e9}").expect("non-ascii");
        assert_eq!(url.path(), "/api/v1/orgs/caf%C3%A9");
    }

    #[test]
    fn build_url_refuses_segment_breaking_path_values() {
        for bad in ["a/b", "a%2Fb", "a?x=1", "a#f", "..", ""] {
            let result = build_url_for_org_id(bad);
            assert!(
                matches!(result, Err(MistError::InvalidRequest { .. })),
                "{bad:?} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn build_url_refuses_unknown_path_parameter() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );
        let path = BTreeMap::from([
            ("org_id".to_owned(), ORG_ID.to_owned()),
            ("bogus".to_owned(), "x".to_owned()),
        ]);
        let result = client.build_url("getOrg", &path, &BTreeMap::new(), None);
        assert!(matches!(result, Err(MistError::InvalidRequest { .. })));
    }

    #[test]
    fn http_client_builds_url_with_query_parameters() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
        let mut query = BTreeMap::new();
        query.insert("limit".to_owned(), serde_json::json!(100));
        query.insert("page".to_owned(), serde_json::json!(2));

        let url = client
            .build_url("listOrgSites", &path, &query, None)
            .expect("build URL");
        let query_str = url.query().expect("query string");
        assert!(query_str.contains("limit=100"));
        assert!(query_str.contains("page=2"));
    }

    #[test]
    fn build_url_threads_the_cursor_value_into_the_next_request() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
        // The stored request context still carries page 1's own query values;
        // the cursor for page 2 must override rather than duplicate them.
        let mut query = BTreeMap::new();
        query.insert("limit".to_owned(), serde_json::json!(10));
        query.insert("page".to_owned(), serde_json::json!(1));

        let cursor = MistCursor::new(
            "listOrgSites".to_owned(),
            &Url::parse("https://api.mist.com/").expect("origin"),
            PaginationMode::PageLimit,
            "2".to_owned(),
        )
        .expect("cursor");

        let url = client
            .build_url("listOrgSites", &path, &query, Some(&cursor))
            .expect("build URL");
        let query_str = url.query().expect("query string");
        assert!(query_str.contains("page=2"), "{query_str}");
        assert!(!query_str.contains("page=1"), "{query_str}");
        assert_eq!(query_str.matches("page=").count(), 1, "{query_str}");
    }

    #[test]
    fn derive_next_cursor_extracts_search_after_from_the_next_url() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        // Mirrors the real Mist response shape: `next` is a relative URL, and
        // `search_after` is the only part of it that changes between pages.
        let body = MistResponseBody::Json(serde_json::json!({
            "start": 0,
            "end": 0,
            "limit": 10,
            "total": 25,
            "results": [],
            "next": format!(
                "/api/v1/orgs/{ORG_ID}/alarms/search?limit=10&search_after=%5B123%2C+%22abc%22%5D"
            ),
        }));

        let cursor = client
            .derive_next_cursor("searchOrgAlarms", &body, None)
            .expect("cursor");
        assert_eq!(cursor.value(), "[123, \"abc\"]");
        assert_eq!(cursor.mode(), PaginationMode::SearchAfter);
    }

    #[test]
    fn derive_next_cursor_is_none_for_non_paginated_operations() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let body = MistResponseBody::Json(serde_json::json!({
            "id": ORG_ID,
            "next": "cursor-token-123"
        }));

        // getOrg is not paginated
        assert!(client.derive_next_cursor("getOrg", &body, None).is_none());
    }

    #[test]
    fn derive_next_cursor_advances_page_limit_operations_from_headers() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        // listOrgSites returns a bare array; the only pagination signal is
        // the X-Page-* headers.
        let body = MistResponseBody::Json(serde_json::json!([]));

        let more_pages = MistPageInfo {
            page: Some(1),
            limit: Some(10),
            total: Some(25),
        };
        let cursor = client
            .derive_next_cursor("listOrgSites", &body, Some(&more_pages))
            .expect("cursor for remaining pages");
        assert_eq!(cursor.value(), "2");
        assert_eq!(cursor.mode(), PaginationMode::PageLimit);

        let last_page = MistPageInfo {
            page: Some(3),
            limit: Some(10),
            total: Some(25),
        };
        assert!(
            client
                .derive_next_cursor("listOrgSites", &body, Some(&last_page))
                .is_none(),
            "page 3 * limit 10 already covers all 25 results"
        );
    }

    #[test]
    fn derive_next_cursor_refuses_a_zero_page_limit_instead_of_looping_forever() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );
        let body = MistResponseBody::Json(serde_json::json!([]));
        let zero_limit = MistPageInfo {
            page: Some(7),
            limit: Some(0),
            total: Some(5),
        };
        assert!(
            client
                .derive_next_cursor("listOrgSites", &body, Some(&zero_limit))
                .is_none(),
            "a zero page size must not be treated as always-more-pages"
        );
    }

    #[test]
    fn derive_next_cursor_does_not_overflow_on_a_maximal_page_number() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );
        let body = MistResponseBody::Json(serde_json::json!([]));
        let max_page = MistPageInfo {
            page: Some(u64::MAX),
            limit: Some(1),
            total: Some(u64::MAX),
        };
        assert!(
            client
                .derive_next_cursor("listOrgSites", &body, Some(&max_page))
                .is_none(),
            "current_page + 1 must not wrap past u64::MAX"
        );
    }

    fn org_request() -> MistRequest {
        MistRequest {
            operation_id: "getOrg".to_owned(),
            path: BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]),
            query: BTreeMap::new(),
            json: None,
            cursor: None,
        }
    }

    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Generate a self-signed `localhost` certificate and a matching rustls
    /// server config, mirroring the pattern mecmcp-http's own tests use to
    /// exercise `HttpRequest::from_absolute_url`'s https-only enforcement.
    fn tls_material() -> (String, rustls::ServerConfig) {
        ensure_crypto_provider();
        let key_pair = rcgen::KeyPair::generate().expect("key pair");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");

        let cert_pem = cert.pem();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .expect("server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        (cert_pem, server_config)
    }

    async fn read_request_head<S>(stream: &mut S)
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while stream.read_exact(&mut byte).await.is_ok() {
            seen.push(byte[0]);
            if seen.ends_with(b"\r\n\r\n") {
                return;
            }
        }
    }

    /// Serve one canned raw HTTP/1.1 response per accepted TLS connection, in
    /// order. Each canned response declares `Connection: close`, so the
    /// client opens a fresh connection per retry -- which is also why
    /// `responses` must be consumed in call order, not concurrently.
    async fn bind_local() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock TLS server");
        let port = listener.local_addr().expect("addr").port();
        (listener, port)
    }

    fn serve_https(
        listener: tokio::net::TcpListener,
        server_config: rustls::ServerConfig,
        responses: Vec<String>,
    ) {
        use tokio::io::AsyncWriteExt;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            for response in responses {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                read_request_head(&mut tls).await;
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            }
        });
    }

    fn ok_org_response() -> String {
        let body = serde_json::json!({"id": ORG_ID, "name": "Test Org"}).to_string();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn rate_limited_response(retry_after_secs: u64) -> String {
        format!(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {retry_after_secs}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    #[tokio::test]
    async fn standard_priority_is_denied_while_reserved_headroom_stays_available() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        // One connection: only the Reserved call below should ever reach the
        // network, since Standard's non-reserved pool is zero.
        serve_https(listener, server_config, vec![ok_org_response()]);

        let client = HttpMistClient::from_test_parts_with_config(
            Url::parse(&format!("https://localhost:{port}")).expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            HttpMistClientConfig {
                hourly_call_budget: 1,
                human_reserve: 1,
                ..HttpMistClientConfig::default()
            },
            vec![cert_pem],
        );

        // Standard's cap (hourly_call_budget - human_reserve) is 0: denied
        // before any network attempt, and the mock server sees no connection
        // for it.
        let denied = client
            .execute_as(org_request(), CallPriority::Standard)
            .await;
        assert_eq!(
            denied,
            Err(MistError::BudgetExhausted {
                used: 0,
                hourly_limit: 1,
                human_reserve: 1,
            })
        );

        // Reserved may still draw on the full hourly budget.
        let reserved = client
            .execute_as(org_request(), CallPriority::Reserved)
            .await;
        assert!(reserved.is_ok(), "reserved headroom must stay available");

        // The whole hourly budget, reserve included, is now spent.
        let fully_denied = client
            .execute_as(org_request(), CallPriority::Reserved)
            .await;
        assert_eq!(
            fully_denied,
            Err(MistError::BudgetExhausted {
                used: 1,
                hourly_limit: 1,
                human_reserve: 1,
            })
        );
    }

    #[tokio::test]
    async fn tool_output_can_report_remaining_budget() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        serve_https(listener, server_config, vec![ok_org_response()]);

        let client = HttpMistClient::from_test_parts_with_config(
            Url::parse(&format!("https://localhost:{port}")).expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            HttpMistClientConfig {
                hourly_call_budget: 5_000,
                human_reserve: 250,
                ..HttpMistClientConfig::default()
            },
            vec![cert_pem],
        );

        let before = client.budget_status().expect("http client tracks budget");
        assert_eq!(before.used, 0);
        assert_eq!(before.remaining_standard, 5_000 - 250);
        assert_eq!(before.remaining_reserved, 5_000);

        client.execute(org_request()).await.expect("call succeeds");

        let after = client.budget_status().expect("http client tracks budget");
        assert_eq!(after.used, 1);
        assert_eq!(after.remaining_standard, 5_000 - 250 - 1);
        assert_eq!(after.remaining_reserved, 5_000 - 1);
    }

    #[tokio::test]
    async fn retries_honour_retry_after_and_then_succeed() {
        // Fails the first 2 attempts with Retry-After: 0, succeeds on the
        // 3rd -- exactly what max_429_retries: 2 allows.
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        serve_https(
            listener,
            server_config,
            vec![
                rate_limited_response(0),
                rate_limited_response(0),
                ok_org_response(),
            ],
        );

        let client = HttpMistClient::from_test_parts_with_config(
            Url::parse(&format!("https://localhost:{port}")).expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            HttpMistClientConfig {
                max_429_retries: 2,
                max_retry_wait: std::time::Duration::from_millis(200),
                ..HttpMistClientConfig::default()
            },
            vec![cert_pem],
        );

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.execute(org_request()),
        )
        .await
        .expect("bounded retries complete promptly")
        .expect("succeeds after honouring Retry-After twice");
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn retries_give_up_after_the_bounded_attempt_count() {
        // The mock never stops returning 429; the client must give up after
        // max_429_retries rather than retrying forever.
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        serve_https(
            listener,
            server_config,
            vec![
                rate_limited_response(0),
                rate_limited_response(0),
                rate_limited_response(0),
            ],
        );

        let client = HttpMistClient::from_test_parts_with_config(
            Url::parse(&format!("https://localhost:{port}")).expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            HttpMistClientConfig {
                max_429_retries: 2,
                max_retry_wait: std::time::Duration::from_millis(200),
                ..HttpMistClientConfig::default()
            },
            vec![cert_pem],
        );

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.execute(org_request()),
        )
        .await
        .expect("bounded retries must not hang the caller");

        assert_eq!(
            result,
            Err(MistError::RateLimited {
                retry_after_secs: Some(0),
            })
        );
    }
}
