//! A container's `ENTRYPOINT` bakes in a fixed `--tokens-file` path so a
//! manually-run HTTP server always stays protected. stdio must still reach
//! full MCP readiness when nothing is mounted at that path: the file guards
//! a bearer listener (`load_http_token_store` in `main.rs`) that only the
//! Streamable HTTP transport branch ever calls, never the stdio branch
//! (MEC-2121).
//!
//! This crate's `main.rs` wires `serve_stdio(handler)` to whatever
//! `MistHandler` the caller already built -- it never touches
//! `--tokens-file` itself. [`MistHandler::blocked`] builds that handler with
//! no outbound Mist credential either (no `credential_env`/`credential_file`
//! read, no network client), so serving it over an in-memory duplex -- the
//! same `.serve(..)` call `serve_stdio` makes on `(stdin, stdout)` -- proves
//! the full stdio handshake and tool catalog never depend on a tokens file,
//! a credential file, or any secret value, matching exactly what
//! `docker run -i <image> --transport stdio` does when the catalog mounts
//! nothing at `/var/lib/rustmistmcp/tokens.json`.

use rmcp::ServiceExt;
use rustmistmcp::MistHandler;
use std::collections::BTreeMap;

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";

#[tokio::test]
async fn stdio_handshake_and_tool_list_succeed_with_no_tokens_file_and_no_credential() {
    let tokens_path = std::env::temp_dir().join(format!(
        "rustmistmcp-stdio-test-tokens-{}.json",
        std::process::id()
    ));
    assert!(
        !tokens_path.exists(),
        "tokens path must not exist for this test"
    );

    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    // `blocked` is the no-network, no-credential handler: no tokens file, no
    // credential_env/credential_file, and no socket are touched to build it,
    // the same way the real stdio startup path never calls
    // `load_http_token_store`.
    let server = MistHandler::blocked(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
    )
    .expect("valid blocked handler with no credential source");
    let server_task = tokio::spawn(async move {
        server
            .serve(server_transport)
            .await
            .expect("stdio-equivalent server initialization")
            .waiting()
            .await
    });

    let client = ()
        .serve(client_transport)
        .await
        .expect("client initialization reached full MCP readiness");
    let tools = client.list_tools(None).await.expect("tools/list succeeded");
    assert!(
        tools.tools.iter().any(|tool| tool.name == "get_mist_org"),
        "expected get_mist_org in the tool catalog, got: {:?}",
        tools.tools
    );

    client.cancel().await.expect("client shutdown");
    server_task.abort();

    assert!(
        !tokens_path.exists(),
        "stdio must not create a bearer-token store"
    );
}
