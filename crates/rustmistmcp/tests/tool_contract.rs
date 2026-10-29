//! In-memory contract tests for the curated Mist MCP read surface.

use async_trait::async_trait;
use rmcp::{ServiceExt, model::CallToolRequestParams};
use rustmistmcp::{KNOWN_TOOLS, MistHandler, RESTRICTED_TOOLS};
use rustmistmcp_core::{
    MistClient, MistCursor, MistError, MistRequest, MistResponse, MistResponseBody, PaginationMode,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
const SITE_ID: &str = "22222222-2222-2222-2222-222222222222";

fn site_map() -> BTreeMap<String, String> {
    BTreeMap::from([(SITE_ID.to_owned(), ORG_ID.to_owned())])
}

#[tokio::test]
async fn registry_contains_only_the_approved_read_tools() {
    const EXPECTED: &[&str] = &[
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
    const EXPECTED_RESTRICTED: &[&str] = &[
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

    assert_eq!(KNOWN_TOOLS, EXPECTED);
    assert_eq!(RESTRICTED_TOOLS, EXPECTED_RESTRICTED);

    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server = MistHandler::blocked("https://api.mist.com/", vec![ORG_ID.to_owned()], site_map())
        .expect("valid blocked handler");
    let server_task = tokio::spawn(async move {
        server
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");

    let info = client.peer_info().expect("server info");
    assert_eq!(
        info.server_info.as_ref().expect("server info present").name,
        "rustmistmcp"
    );
    let tools = client.list_tools(None).await.expect("tool list");
    let names: Vec<_> = tools.tools.iter().map(|tool| tool.name.as_ref()).collect();
    let ordinary_names = EXPECTED
        .iter()
        .copied()
        .filter(|name| !EXPECTED_RESTRICTED.contains(name))
        .collect::<Vec<_>>();
    assert_eq!(names, ordinary_names);

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

/// `--tool-mode compact` through the real `list_tools`: a caller-less (stdio)
/// list is the compact dispatchers minus the restricted one.
#[tokio::test]
async fn compact_tool_mode_lists_only_the_unrestricted_dispatchers_over_mcp() {
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server = MistHandler::blocked("https://api.mist.com/", vec![ORG_ID.to_owned()], site_map())
        .expect("valid blocked handler")
        .with_tool_mode(mecmcp_runtime::cli::ToolMode::Compact);
    let server_task = tokio::spawn(async move {
        server
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");

    let tools = client.list_tools(None).await.expect("tool list");
    let mut names: Vec<_> = tools
        .tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "get_mist_operation_schema",
            "invoke_mist_read",
            "search_mist_operations"
        ]
    );

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn registry_schemas_are_strict_and_dispatchers_accept_no_raw_http_inputs() {
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server = MistHandler::blocked("https://api.mist.com/", vec![ORG_ID.to_owned()], site_map())
        .expect("valid blocked handler");
    let server_task = tokio::spawn(async move {
        server
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let tools = client.list_tools(None).await.expect("tool list").tools;

    for tool in &tools {
        assert_eq!(
            tool.input_schema.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false)),
            "{} must reject unknown fields",
            tool.name
        );
    }

    let get_org = tools
        .iter()
        .find(|tool| tool.name == "get_mist_org")
        .expect("get_mist_org schema");
    assert_eq!(
        get_org
            .input_schema
            .get("required")
            .and_then(serde_json::Value::as_array)
            .expect("required fields"),
        &[serde_json::json!("org_id")]
    );
    assert_eq!(schema_property_names(get_org), BTreeSet::from(["org_id"]),);

    for name in ["invoke_mist_read"] {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .expect("dispatcher schema");
        assert_eq!(
            schema_property_names(tool),
            BTreeSet::from(["cursor", "operation_id", "path", "query"]),
        );
        assert_eq!(
            tool.input_schema["properties"]["cursor"]["maxLength"],
            serde_json::json!(rustmistmcp_core::MAX_ENCODED_CURSOR_BYTES)
        );
        for forbidden in ["method", "url", "headers", "body", "file"] {
            assert!(
                !schema_property_names(tool).contains(forbidden),
                "{name} must not accept {forbidden}"
            );
        }
    }

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

fn schema_property_names(tool: &rmcp::model::Tool) -> BTreeSet<&str> {
    tool.input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .expect("schema properties")
        .keys()
        .map(String::as_str)
        .collect()
}

#[derive(Default)]
struct RecordingClient {
    requests: Mutex<Vec<MistRequest>>,
}

#[derive(Default)]
struct PagingClient {
    requests: Mutex<Vec<MistRequest>>,
}

#[async_trait]
impl MistClient for PagingClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        self.requests
            .lock()
            .expect("request recorder")
            .push(request.clone());
        let mode = match request.operation_id.as_str() {
            "listOrgSites" => PaginationMode::PageLimit,
            "searchSiteWirelessClients" => PaginationMode::SearchAfter,
            other => panic!("unexpected paginated operation: {other}"),
        };
        let body = match request.operation_id.as_str() {
            "listOrgSites" => serde_json::json!([]),
            "searchSiteWirelessClients" => serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 10,
                "total": 0,
                "results": []
            }),
            _ => unreachable!(),
        };
        Ok(MistResponse {
            operation_id: request.operation_id.clone(),
            status: 200,
            body: MistResponseBody::Json(body),
            cursor: Some(MistCursor::new(
                request.operation_id,
                &url::Url::parse("https://api.mist.com/").expect("origin"),
                mode,
                match mode {
                    PaginationMode::PageLimit => "2".to_owned(),
                    _ => "next-page".to_owned(),
                },
            )?),
            page: None,
        })
    }
}

#[derive(Default)]
struct FailingRecordingClient {
    requests: Mutex<Vec<MistRequest>>,
}

#[async_trait]
impl MistClient for FailingRecordingClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        self.requests.lock().expect("recorder").push(request);
        Err(MistError::Service("recorded".to_owned()))
    }
}

#[async_trait]
impl MistClient for RecordingClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        self.requests
            .lock()
            .expect("request recorder")
            .push(request.clone());
        Ok(MistResponse {
            operation_id: request.operation_id,
            status: 200,
            body: MistResponseBody::Json(serde_json::json!({"name": "Example Org"})),
            cursor: None,
            page: None,
        })
    }
}

#[tokio::test]
async fn named_get_org_uses_only_its_exact_catalog_operation_and_target() {
    let recorder = Arc::new(RecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");

    let result = client
        .call_tool(CallToolRequestParams::new("get_mist_org").with_arguments(
            serde_json::from_value(serde_json::json!({"org_id": ORG_ID})).expect("arguments"),
        ))
        .await
        .expect("MCP call");
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let envelope: serde_json::Value =
        serde_json::from_str(&result.content[0].as_text().expect("text result").text)
            .expect("JSON envelope");
    assert_eq!(envelope["operation_id"], "getOrg");
    assert_eq!(envelope["target"], format!("org/{ORG_ID}"));
    assert_eq!(envelope["status"], 200);
    assert_eq!(envelope["content_type"], "application/json");
    assert_eq!(envelope["data"]["name"], "Example Org");
    assert_eq!(envelope["truncated"], false);

    {
        let requests = recorder.requests.lock().expect("request recorder");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].operation_id, "getOrg");
        assert_eq!(
            requests[0].path,
            std::collections::BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())])
        );
        assert!(requests[0].query.is_empty());
        assert!(requests[0].json.is_none());
        assert!(requests[0].cursor.is_none());
    }

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn every_remote_named_workflow_resolves_to_its_one_approved_operation() {
    let recorder = Arc::new(FailingRecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let site = SITE_ID;
    let device = "33333333-3333-3333-3333-333333333333";
    let cases = [
        ("get_mist_self", serde_json::json!({}), "getSelf"),
        (
            "get_mist_org",
            serde_json::json!({"org_id": ORG_ID}),
            "getOrg",
        ),
        (
            "list_mist_sites",
            serde_json::json!({"org_id": ORG_ID, "limit": 25, "page": 2}),
            "listOrgSites",
        ),
        (
            "get_mist_site",
            serde_json::json!({"site_id": site}),
            "getSiteInfo",
        ),
        (
            "search_mist_inventory",
            serde_json::json!({"org_id": ORG_ID, "text": "edge", "limit": 25}),
            "searchOrgInventory",
        ),
        (
            "get_mist_device",
            serde_json::json!({"site_id": site, "device_id": device}),
            "getSiteDevice",
        ),
        (
            "get_mist_device_stats",
            serde_json::json!({"site_id": site, "device_id": device, "fields": "name,status"}),
            "getSiteDeviceStats",
        ),
        (
            "list_mist_wlans",
            serde_json::json!({"site_id": site, "limit": 25, "page": 1}),
            "listSiteWlans",
        ),
        (
            "search_mist_clients",
            serde_json::json!({"site_id": site, "text": "client", "limit": 25}),
            "searchSiteWirelessClients",
        ),
        (
            "search_mist_events",
            serde_json::json!({"site_id": site, "type": "device", "limit": 25}),
            "searchSiteSystemEvents",
        ),
        (
            "search_mist_alarms",
            serde_json::json!({"site_id": site, "acked": false, "limit": 25}),
            "searchSiteAlarms",
        ),
        (
            "search_mist_alarms",
            serde_json::json!({"org_id": ORG_ID, "limit": 25}),
            "searchOrgAlarms",
        ),
        (
            "search_mist_alarms",
            serde_json::json!({"site_id": site, "mode": "count"}),
            "countSiteAlarms",
        ),
        (
            "search_mist_alarms",
            serde_json::json!({"org_id": ORG_ID, "mode": "count"}),
            "countOrgAlarms",
        ),
        (
            "list_mist_alarm_definitions",
            serde_json::json!({}),
            "listAlarmDefinitions",
        ),
        (
            "search_mist_audit_logs",
            serde_json::json!({"org_id": ORG_ID, "message": "changed", "limit": 25}),
            "listOrgAuditLogs",
        ),
        (
            "list_mist_sle_metrics",
            serde_json::json!({"site_id": site, "scope": "site", "scope_id": site}),
            "listSiteSlesMetrics",
        ),
        (
            "get_mist_sle",
            serde_json::json!({"site_id": site, "scope": "site", "scope_id": site, "metric": "coverage"}),
            "getSiteSleSummaryTrend",
        ),
        (
            "get_mist_insight",
            serde_json::json!({"site_id": site, "metrics": "num_clients", "limit": 25}),
            "getSiteInsightMetrics",
        ),
        (
            "troubleshoot_mist",
            serde_json::json!({"site_id": site, "app": "zoom", "limit": 25}),
            "listSiteTroubleshootCalls",
        ),
        (
            "list_mist_rogues",
            serde_json::json!({"site_id": site, "type": "others", "limit": 25}),
            "listSiteRogueAPs",
        ),
        (
            "get_mist_rrm",
            serde_json::json!({"site_id": site}),
            "getSiteCurrentChannelPlanning",
        ),
        (
            "list_mist_upgrades",
            serde_json::json!({"site_id": site, "status": "upgrading"}),
            "listSiteDeviceUpgrades",
        ),
    ];
    for (tool, arguments, expected_operation) in cases {
        let before = recorder.requests.lock().expect("recorder").len();
        let result = client
            .call_tool(
                CallToolRequestParams::new(tool)
                    .with_arguments(serde_json::from_value(arguments).expect("arguments")),
            )
            .await
            .expect("MCP call");
        assert_eq!(result.is_error, Some(true), "{tool} uses recording failure");
        if RESTRICTED_TOOLS.contains(&tool) {
            assert_eq!(
                recorder.requests.lock().expect("recorder").len(),
                before,
                "{tool} must be denied without caller context"
            );
            continue;
        }
        let request = recorder
            .requests
            .lock()
            .expect("recorder")
            .last()
            .cloned()
            .unwrap_or_else(|| panic!("{tool} did not invoke the client"));
        assert_eq!(request.operation_id, expected_operation, "{tool}");
    }

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn list_orgs_is_a_bounded_local_view_and_never_substitutes_get_self() {
    let second_org = "44444444-4444-4444-4444-444444444444";
    let recorder = Arc::new(FailingRecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned(), second_org.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let result = client
        .call_tool(CallToolRequestParams::new("list_mist_orgs"))
        .await
        .expect("MCP call");
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let value: serde_json::Value =
        serde_json::from_str(&result.content[0].as_text().expect("text").text).expect("JSON");
    assert_eq!(value["source"], "local_configured_allowlist");
    assert_eq!(
        value["organizations"]
            .as_array()
            .expect("organizations")
            .len(),
        2
    );
    assert_eq!(value["organizations"][0]["target"], format!("org/{ORG_ID}"));
    assert!(recorder.requests.lock().expect("recorder").is_empty());

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn dispatchers_enforce_exact_read_class_and_reject_raw_http_fields() {
    let recorder = Arc::new(RecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");

    let ordinary = client
        .call_tool(
            CallToolRequestParams::new("invoke_mist_read").with_arguments(
                serde_json::from_value(serde_json::json!({
                    "operation_id": "getOrg",
                    "path": {"org_id": ORG_ID}
                }))
                .expect("arguments"),
            ),
        )
        .await
        .expect("ordinary call");
    assert_ne!(ordinary.is_error, Some(true), "{ordinary:?}");
    assert_eq!(recorder.requests.lock().expect("recorder").len(), 1);

    let wrong_class = client
        .call_tool(
            CallToolRequestParams::new("invoke_mist_read").with_arguments(
                serde_json::from_value(serde_json::json!({"operation_id": "getSelf"}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("wrong-class call");
    assert_eq!(wrong_class.is_error, Some(true));
    assert_eq!(recorder.requests.lock().expect("recorder").len(), 1);

    let privileged = client
        .call_tool(
            CallToolRequestParams::new("invoke_mist_privileged_read").with_arguments(
                serde_json::from_value(serde_json::json!({"operation_id": "getSelf"}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("privileged call");
    assert_eq!(privileged.is_error, Some(true), "{privileged:?}");
    assert_eq!(recorder.requests.lock().expect("recorder").len(), 1);

    let raw_http = client
        .call_tool(
            CallToolRequestParams::new("invoke_mist_read").with_arguments(
                serde_json::from_value(serde_json::json!({
                    "operation_id": "getOrg",
                    "path": {"org_id": ORG_ID},
                    "method": "DELETE",
                    "url": "https://evil.example/",
                    "body": {}
                }))
                .expect("arguments"),
            ),
        )
        .await
        .expect("strict-schema call");
    assert_eq!(raw_http.is_error, Some(true));
    assert_eq!(recorder.requests.lock().expect("recorder").len(), 1);

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn cursor_only_continuations_preserve_org_and_site_request_context() {
    let recorder = Arc::new(PagingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");

    let cases = [
        serde_json::json!({
            "operation_id": "listOrgSites",
            "path": {"org_id": ORG_ID},
            "query": {"limit": 25, "page": 2}
        }),
        serde_json::json!({
            "operation_id": "searchSiteWirelessClients",
            "path": {"site_id": SITE_ID},
            "query": {"limit": 10, "search_after": "first"}
        }),
    ];
    for arguments in cases {
        let operation_id = arguments["operation_id"]
            .as_str()
            .expect("operation")
            .to_owned();
        let first = client
            .call_tool(
                CallToolRequestParams::new("invoke_mist_read")
                    .with_arguments(serde_json::from_value(arguments.clone()).expect("arguments")),
            )
            .await
            .expect("first page");
        assert_ne!(first.is_error, Some(true), "{first:?}");
        let envelope: serde_json::Value =
            serde_json::from_str(&first.content[0].as_text().expect("text").text).expect("JSON");
        let cursor = envelope["next_cursor"]
            .as_str()
            .expect("continuation cursor")
            .to_owned();

        let second = client
            .call_tool(
                CallToolRequestParams::new("invoke_mist_read").with_arguments(
                    serde_json::from_value(serde_json::json!({
                        "operation_id": operation_id,
                        "cursor": cursor
                    }))
                    .expect("arguments"),
                ),
            )
            .await
            .expect("continuation page");
        assert_ne!(second.is_error, Some(true), "{second:?}");

        let requests = recorder.requests.lock().expect("request recorder");
        let previous = &requests[requests.len() - 2];
        let continued = &requests[requests.len() - 1];
        assert_eq!(continued.operation_id, previous.operation_id);
        assert_eq!(continued.path, previous.path);
        assert_eq!(continued.query, previous.query);
        assert!(continued.cursor.is_some());
    }

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn catalog_metadata_is_local_bounded_and_returns_exact_schema_records() {
    let recorder = Arc::new(FailingRecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");

    let search = client
        .call_tool(
            CallToolRequestParams::new("search_mist_operations").with_arguments(
                serde_json::from_value(serde_json::json!({
                    "query": "org",
                    "capability": "ordinary_read",
                    "target": "org",
                    "limit": 5
                }))
                .expect("arguments"),
            ),
        )
        .await
        .expect("search");
    assert_ne!(search.is_error, Some(true), "{search:?}");
    let matches: Vec<serde_json::Value> =
        serde_json::from_str(&search.content[0].as_text().expect("text").text).expect("JSON");
    assert!(!matches.is_empty());
    assert!(matches.len() <= 5);
    assert!(
        matches
            .iter()
            .all(|item| item["capability"] == "ordinary_read")
    );
    assert!(matches.iter().all(|item| {
        item["target_selectors"]
            .as_array()
            .is_some_and(|targets| targets.contains(&serde_json::json!("org")))
    }));

    let schema = client
        .call_tool(
            CallToolRequestParams::new("get_mist_operation_schema").with_arguments(
                serde_json::from_value(serde_json::json!({"operation_id": "getOrg"}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("schema");
    assert_ne!(schema.is_error, Some(true), "{schema:?}");
    let operation: serde_json::Value =
        serde_json::from_str(&schema.content[0].as_text().expect("text").text).expect("JSON");
    assert_eq!(operation["operation_id"], "getOrg");
    assert_eq!(operation["method"], "GET");
    assert_eq!(operation["path"], "/api/v1/orgs/{org_id}");
    assert_eq!(operation["capability"], "ordinary_read");
    assert!(operation.get("parameters").is_some());
    assert!(operation.get("responses").is_some());
    assert!(recorder.requests.lock().expect("recorder").is_empty());

    // Schema introspection no longer requires execution rights (issue #97.2)
    let privileged_schema = client
        .call_tool(
            CallToolRequestParams::new("get_mist_operation_schema").with_arguments(
                serde_json::from_value(serde_json::json!({"operation_id": "getSelf"}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("privileged schema");
    // Introspection now succeeds even for privileged operations
    assert_ne!(privileged_schema.is_error, Some(true));
    let privileged_op: serde_json::Value =
        serde_json::from_str(&privileged_schema.content[0].as_text().expect("text").text)
            .expect("JSON");
    assert_eq!(privileged_op["operation_id"], "getSelf");
    assert_eq!(privileged_op["capability"], "privileged_read");

    let oversized = client
        .call_tool(
            CallToolRequestParams::new("search_mist_operations").with_arguments(
                serde_json::from_value(serde_json::json!({"query": "a", "limit": 51}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("oversized");
    assert_eq!(oversized.is_error, Some(true));

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn site_reads_require_startup_discovery_even_without_remote_auth() {
    let recorder = Arc::new(FailingRecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let result = client
        .call_tool(CallToolRequestParams::new("get_mist_site").with_arguments(
            serde_json::from_value(serde_json::json!({"site_id": SITE_ID})).expect("arguments"),
        ))
        .await
        .expect("site call");
    assert_eq!(result.is_error, Some(true));
    assert!(recorder.requests.lock().expect("recorder").is_empty());
    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[tokio::test]
async fn invalid_targets_parameters_limits_and_msp_selectors_never_reach_the_client() {
    let recorder = Arc::new(FailingRecordingClient::default());
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder.clone(),
    )
    .expect("handler");
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let rejected = [
        serde_json::json!({"operation_id":"getOrg","path":{"org_id":"NOT-A-UUID"}}),
        serde_json::json!({"operation_id":"getOrg","path":{"org_id":ORG_ID},"query":{"surprise":true}}),
        serde_json::json!({"operation_id":"listOrgSites","path":{"org_id":ORG_ID},"query":{"limit":101}}),
        serde_json::json!({"operation_id":"getMspDetails","path":{"msp_id":ORG_ID}}),
        serde_json::json!({"operation_id":"getOrg","path":{"org_id":ORG_ID},"cursor":"00"}),
    ];
    for arguments in rejected {
        let result = client
            .call_tool(
                CallToolRequestParams::new("invoke_mist_read")
                    .with_arguments(serde_json::from_value(arguments).expect("arguments")),
            )
            .await
            .expect("MCP call");
        assert_eq!(result.is_error, Some(true), "{result:?}");
    }
    assert!(recorder.requests.lock().expect("recorder").is_empty());

    client.cancel().await.expect("client shutdown");
    server_task.abort();
}

#[test]
fn server_instructions_do_not_claim_read_only() {
    use rmcp::ServerHandler;

    let handler =
        MistHandler::blocked("https://api.mist.com/", vec![ORG_ID.to_owned()], site_map())
            .expect("valid blocked handler");
    let instructions = handler
        .get_info()
        .instructions
        .expect("server instructions present");
    // #120: the instructions called the server read-only after the WAN edge
    // change-set write tools had been registered.
    assert!(
        !instructions.to_ascii_lowercase().contains("read-only"),
        "instructions must not describe a server with mutating tools as read-only: {instructions}"
    );
    for tool in [
        "plan_mist_change",
        "approve_mist_change_set",
        "apply_mist_change_set",
    ] {
        assert!(KNOWN_TOOLS.contains(&tool));
        assert!(
            instructions.contains(tool),
            "instructions must name the {tool} lifecycle step"
        );
    }
}
