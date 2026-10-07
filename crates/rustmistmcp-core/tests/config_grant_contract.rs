//! Contract tests for strict Mist profile metadata and grants.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use mecmcp_auth::{Grant, TokenEntry, TokenStore};
use rustmistmcp_core::{ConfigError, MistAction, MistConfig, MistGrant, MistTarget};
use tempfile::TempDir;

const ORG: &str = "123e4567-e89b-42d3-a456-426614174000";
const OTHER_ORG: &str = "223e4567-e89b-42d3-a456-426614174000";
const SITE: &str = "323e4567-e89b-42d3-a456-426614174000";

fn credential(temp: &TempDir) -> std::path::PathBuf {
    let path = temp.path().join("mist-token");
    fs::write(&path, "must-not-be-read-by-config").expect("credential fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("credential mode");
    path
}

fn config_json(credential_file: &std::path::Path, endpoint: &str) -> String {
    serde_json::json!({
        "version": 1,
        "endpoint": endpoint,
        "credential_file": credential_file,
        "allowed_orgs": [ORG, OTHER_ORG],
    })
    .to_string()
}

fn config_from(temp: &TempDir, json: String) -> Result<MistConfig, rustmistmcp_core::ConfigError> {
    let path = temp.path().join("mist.json");
    fs::write(&path, json).expect("config fixture");
    MistConfig::from_path(&path)
}

#[test]
fn strict_singleton_v1_config_accepts_only_safe_profile_metadata() {
    let temp = TempDir::new().expect("tempdir");
    let credential_file = credential(&temp);
    let config = config_from(
        &temp,
        config_json(&credential_file, "https://api.eu.mist.com/"),
    )
    .expect("valid config");

    assert_eq!(config.version, 1);
    assert_eq!(config.endpoint, "https://api.eu.mist.com/");
    assert_eq!(config.credential_file, Some(credential_file));
    assert_eq!(config.allowed_orgs, [ORG, OTHER_ORG]);
    let serialized = serde_json::to_string(&config).expect("serialize config");
    assert!(serialized.contains("credential_file"));
    assert!(!serialized.contains("must-not-be-read-by-config"));
}

#[test]
fn config_distinguishes_file_and_parse_failures_and_rejects_alternate_shapes() {
    let temp = TempDir::new().expect("tempdir");
    assert!(matches!(
        MistConfig::from_path(&temp.path().join("missing.json")),
        Err(ConfigError::Read(_))
    ));
    assert!(matches!(
        config_from(&temp, "not json".to_owned()),
        Err(ConfigError::Parse(_))
    ));

    let credential_file = credential(&temp);
    for json in [
        serde_json::json!({
            "version": 1, "endpoint": "https://api.mist.com", "credential_file": credential_file,
            "allowed_orgs": [ORG], "token": "never-supported"
        }),
        serde_json::json!({
            "version": 2, "endpoint": "https://api.mist.com", "credential_file": credential_file,
            "allowed_orgs": [ORG]
        }),
        serde_json::json!({
            "version": 1, "endpoint": "https://api.mist.com", "credential_file": credential_file,
            "allowed_orgs": []
        }),
        serde_json::json!({
            "version": 1, "endpoint": "https://api.mist.com", "credential_file": credential_file,
            "allowed_orgs": [ORG, ORG]
        }),
        serde_json::json!({
            "version": 1, "endpoint": "https://api.mist.com", "credential_file": credential_file,
            "allowed_orgs": ["123E4567-E89B-42D3-A456-426614174000"]
        }),
    ] {
        assert!(config_from(&temp, json.to_string()).is_err(), "{json}");
    }

    let too_many_orgs: Vec<_> = (0..257)
        .map(|index| format!("123e4567-e89b-42d3-a456-{index:012x}"))
        .collect();
    let too_many = serde_json::json!({
        "version": 1, "endpoint": "https://api.mist.com", "credential_file": credential_file,
        "allowed_orgs": too_many_orgs,
    });
    assert!(config_from(&temp, too_many.to_string()).is_err());
}

#[test]
fn config_accepts_only_https_mist_regional_roots() {
    let temp = TempDir::new().expect("tempdir");
    let credential_file = credential(&temp);
    for endpoint in [
        "https://api.mist.com",
        "https://api.eu.mist.com/",
        "https://api.gc1.mist.com/",
        "https://api.future-region.mist.com/",
    ] {
        assert!(
            config_from(&temp, config_json(&credential_file, endpoint)).is_ok(),
            "{endpoint}"
        );
    }
    for endpoint in [
        "http://api.mist.com",
        "https://mist.com",
        "https://api.mist.com.evil.example",
        "https://user@api.mist.com",
        "https://127.0.0.1",
        "https://api.mist.com:444",
        "https://api.mist.com/api/v1",
        "https://api.mist.com/?page=1",
        "https://api.mist.com/#fragment",
    ] {
        assert!(
            config_from(&temp, config_json(&credential_file, endpoint)).is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn config_validates_credential_metadata_without_loading_the_secret() {
    let temp = TempDir::new().expect("tempdir");
    let credential_file = credential(&temp);
    assert!(config_from(&temp, config_json(&credential_file, "https://api.mist.com")).is_ok());

    for path in [temp.path().join("relative"), temp.path().join("missing")] {
        assert!(config_from(&temp, config_json(&path, "https://api.mist.com")).is_err());
    }
    assert!(config_from(&temp, config_json(temp.path(), "https://api.mist.com")).is_err());

    let symlink_path = temp.path().join("symlink-token");
    symlink(&credential_file, &symlink_path).expect("symlink fixture");
    assert!(config_from(&temp, config_json(&symlink_path, "https://api.mist.com")).is_err());

    fs::set_permissions(&credential_file, fs::Permissions::from_mode(0o640)).expect("weaken mode");
    assert!(config_from(&temp, config_json(&credential_file, "https://api.mist.com")).is_err());
}

/// A container's `ENTRYPOINT` passes a fixed `--device-mapping` path, and a
/// Docker MCP Toolkit catalog deployment mounts a bind-mount-owned secret
/// file onto an image running as a non-root uid -- a file the image user
/// cannot always read. `credential_env` lets the catalog supply the API
/// token as an environment variable the registry declares under
/// `config.secrets` instead, with the value never on argv or in the
/// inventory JSON (MEC-2121).
#[test]
fn config_accepts_credential_env_and_rejects_both_or_neither_source() {
    let temp = TempDir::new().expect("tempdir");

    let env_only = serde_json::json!({
        "version": 1,
        "endpoint": "https://api.mist.com",
        "credential_env": "RUSTMISTMCP_TOKEN",
        "allowed_orgs": [ORG],
    });
    let config = config_from(&temp, env_only.to_string()).expect("credential_env is valid alone");
    assert_eq!(config.credential_env.as_deref(), Some("RUSTMISTMCP_TOKEN"));
    assert_eq!(config.credential_file, None);
    let serialized = serde_json::to_string(&config).expect("serialize config");
    assert!(serialized.contains("RUSTMISTMCP_TOKEN"));

    let neither = serde_json::json!({
        "version": 1,
        "endpoint": "https://api.mist.com",
        "allowed_orgs": [ORG],
    });
    assert!(config_from(&temp, neither.to_string()).is_err());

    let credential_file = credential(&temp);
    let both = serde_json::json!({
        "version": 1,
        "endpoint": "https://api.mist.com",
        "credential_env": "RUSTMISTMCP_TOKEN",
        "credential_file": credential_file,
        "allowed_orgs": [ORG],
    });
    assert!(config_from(&temp, both.to_string()).is_err());

    for bad_name in ["", "has space", "has-dash", "has.dot"] {
        let bad = serde_json::json!({
            "version": 1,
            "endpoint": "https://api.mist.com",
            "credential_env": bad_name,
            "allowed_orgs": [ORG],
        });
        assert!(config_from(&temp, bad.to_string()).is_err(), "{bad_name:?}");
    }
}

#[test]
fn load_secret_reads_from_whichever_source_is_configured() {
    let temp = TempDir::new().expect("tempdir");

    // Setting process-wide environment variables in-process is unsafe (and
    // forbidden in this workspace) because it races every other test thread
    // reading the environment. The env branch is proven instead by its
    // failure mode: a variable this test never sets still names itself (not
    // a file path) in the error, showing `load_secret` reached
    // `load_from_env` rather than `load_from_file`.
    let env_config = MistConfig {
        version: 1,
        endpoint: "https://api.mist.com".to_owned(),
        credential_env: Some("RUSTMISTMCP_CONTRACT_TEST_TOKEN_UNSET".to_owned()),
        credential_file: None,
        allowed_orgs: vec![ORG.to_owned()],
    };
    let error = match env_config.load_secret() {
        Err(error) => error,
        Ok(_) => panic!("RUSTMISTMCP_CONTRACT_TEST_TOKEN_UNSET must not be set in this test run"),
    };
    assert!(
        error
            .to_string()
            .contains("RUSTMISTMCP_CONTRACT_TEST_TOKEN_UNSET"),
        "{error}"
    );

    let credential_file = credential(&temp);
    let file_config = MistConfig {
        version: 1,
        endpoint: "https://api.mist.com".to_owned(),
        credential_env: None,
        credential_file: Some(credential_file),
        allowed_orgs: vec![ORG.to_owned()],
    };
    let secret = file_config.load_secret().expect("load from file");
    assert_eq!(secret.expose(), "must-not-be-read-by-config");
}

#[test]
fn targets_are_exact_canonical_opaque_subjects() {
    let org = MistTarget::org(ORG).expect("org target");
    let site = MistTarget::site(SITE).expect("site target");
    assert_eq!(org.subject(), format!("org/{ORG}"));
    assert_eq!(site.to_string(), format!("site/{SITE}"));
    assert_eq!(org.id(), ORG);
    assert_eq!(
        serde_json::to_string(&site).expect("serialize target"),
        format!("\"site/{SITE}\"")
    );
    let decoded =
        serde_json::from_str::<MistTarget>(&format!("\"org/{ORG}\"")).expect("deserialize target");
    assert_eq!(decoded, org);

    for subject in [
        ORG,
        "org/123E4567-E89B-42D3-A456-426614174000",
        "org/00000000-0000-0000-0000-000000000000",
        "org/123e4567-e89b-42d3-a456-426614174000/child",
        "organization/123e4567-e89b-42d3-a456-426614174000",
        "org/123e4567-e89b-42d3-a456-426614174000?x=1",
        " org/123e4567-e89b-42d3-a456-426614174000",
    ] {
        assert!(MistTarget::parse(subject).is_err(), "{subject}");
    }
}

fn grant() -> MistGrant {
    MistGrant {
        allowed_operations: vec!["orgs_get".to_owned()],
        actions: vec![MistAction::Update],
        subjects: vec![MistTarget::org(ORG).expect("target")],
    }
}

#[test]
fn malformed_subject_is_rejected_by_parse_and_the_grant_seam() {
    let grant = grant();
    let malformed = format!("org/{ORG}/descendant");
    assert!(MistTarget::parse(&malformed).is_err());
    assert!(!grant.allows_subject(&malformed));
}

#[test]
fn grant_requires_exact_operation_action_and_target() {
    let grant = grant();
    assert!(grant.validate().is_ok());
    assert!(grant.allows_operation("orgs_get"));
    assert!(!grant.allows_operation("orgs_get_extra"));
    assert!(grant.allows_action(MistAction::Update));
    assert!(!grant.allows_action(MistAction::Delete));
    assert!(grant.allows_target(&MistTarget::org(ORG).expect("target")));
    assert!(!grant.allows_target(&MistTarget::site(ORG).expect("target")));
    assert!(!grant.allows_target(&MistTarget::org(OTHER_ORG).expect("target")));
    assert!(grant.allows_subject(&format!("org/{ORG}")));
    assert!(!grant.allows_subject(&format!("org/{ORG}/descendant")));
    assert!(!grant.allows_subject("org/not-a-uuid"));
}

#[test]
fn grant_rejects_empty_duplicate_and_malformed_allowlists() {
    let cases = [
        MistGrant {
            allowed_operations: vec![],
            actions: vec![MistAction::Update],
            subjects: vec![MistTarget::org(ORG).expect("target")],
        },
        MistGrant {
            allowed_operations: vec!["op".to_owned()],
            actions: vec![],
            subjects: vec![MistTarget::org(ORG).expect("target")],
        },
        MistGrant {
            allowed_operations: vec!["op".to_owned()],
            actions: vec![MistAction::Update],
            subjects: vec![],
        },
        MistGrant {
            allowed_operations: vec!["op".to_owned(), "op".to_owned()],
            actions: vec![MistAction::Update],
            subjects: vec![MistTarget::org(ORG).expect("target")],
        },
        MistGrant {
            allowed_operations: vec!["op".to_owned()],
            actions: vec![MistAction::Update, MistAction::Update],
            subjects: vec![MistTarget::org(ORG).expect("target")],
        },
        MistGrant {
            allowed_operations: vec!["op".to_owned()],
            actions: vec![MistAction::Update],
            subjects: vec![
                MistTarget::org(ORG).expect("target"),
                MistTarget::org(ORG).expect("target"),
            ],
        },
        MistGrant {
            allowed_operations: vec!["has space".to_owned()],
            actions: vec![MistAction::Update],
            subjects: vec![MistTarget::org(ORG).expect("target")],
        },
        MistGrant {
            allowed_operations: vec!["x".repeat(257)],
            actions: vec![MistAction::Update],
            subjects: vec![MistTarget::org(ORG).expect("target")],
        },
    ];
    for grant in cases {
        assert!(grant.validate().is_err(), "{grant:?}");
    }

    let too_many_operations = MistGrant {
        allowed_operations: (0..257).map(|index| format!("operation-{index}")).collect(),
        actions: vec![MistAction::Update],
        subjects: vec![MistTarget::org(ORG).expect("target")],
    };
    assert!(too_many_operations.validate().is_err());
    let too_many_subjects = MistGrant {
        allowed_operations: vec!["op".to_owned()],
        actions: vec![MistAction::Update],
        subjects: (0..257)
            .map(|index| {
                MistTarget::org(format!("123e4567-e89b-42d3-a456-{index:012x}")).expect("target")
            })
            .collect(),
    };
    assert!(too_many_subjects.validate().is_err());
}

#[test]
fn token_store_validates_deserialized_mist_grants_at_the_actual_vendor_seam() {
    let valid = serde_json::json!({
        "name": "mist-writer",
        "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "created_at": "2026-07-29T00:00:00Z",
        "grant": {
            "allowed_operations": ["orgs_get"],
            "actions": ["update"],
            "subjects": [format!("org/{ORG}")]
        }
    });
    let entry: TokenEntry<MistGrant> =
        serde_json::from_value(valid).expect("deserialize valid entry");
    assert!(TokenStore::try_new(vec![entry]).is_ok());

    let invalid = serde_json::json!({
        "name": "mist-writer",
        "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "created_at": "2026-07-29T00:00:00Z",
        "grant": {
            "allowed_operations": [],
            "actions": ["update"],
            "subjects": [format!("org/{ORG}")]
        }
    });
    let entry: TokenEntry<MistGrant> =
        serde_json::from_value(invalid).expect("deserialize invalid grant shape");
    assert!(TokenStore::try_new(vec![entry]).is_err());
}
