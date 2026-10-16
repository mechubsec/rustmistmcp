//! The Mist change-set lifecycle: stage, inspect, approve, apply.
//!
//! The state machine, persistence and digests are `mecmcp-changeset`'s. What
//! belongs here is Mist-specific: which read produces the `before` state, how
//! an object is named as a concurrency key, and what verification means.

use crate::server::wan::WanObject;
use mecmcp_changeset::{ChangeSetRecord, ChangeSetState, CoordinatorError, digest};
use rustmistmcp_core::MistGrant;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Map a caller's server-verified `mecmcp_auth::ActorType` to the
/// `mecmcp_audit::ActorType` mecmcp's `approve_change_set` requires.
///
/// `None` -- no authenticated caller context, i.e. the stdio transport --
/// maps to `Unknown` rather than `Human`. Inventing `Human` for an
/// unattributed caller would let stdio silently satisfy the human-approver
/// gate; `Unknown` is the honest fact, and `approve_change_set` refuses it
/// exactly like it refuses `Agent`.
pub(crate) fn actor_type(
    caller: Option<&mecmcp_auth::CallerCtx<MistGrant>>,
) -> mecmcp_audit::ActorType {
    match caller {
        Some(ctx) => match ctx.actor_type {
            mecmcp_auth::ActorType::Human => mecmcp_audit::ActorType::Human,
            mecmcp_auth::ActorType::Agent => mecmcp_audit::ActorType::Agent,
            mecmcp_auth::ActorType::Unknown => mecmcp_audit::ActorType::Unknown,
        },
        None => mecmcp_audit::ActorType::Unknown,
    }
}

/// The approver's identity for `approve_change_set`. No verified-approver
/// assertion path is wired into this server, so it is always token-asserted;
/// strict mode cannot be satisfied.
pub(crate) fn approver_identity(
    caller: Option<&mecmcp_auth::CallerCtx<MistGrant>>,
) -> mecmcp_changeset::ApproverIdentity {
    mecmcp_changeset::ApproverIdentity::TokenAsserted {
        principal: caller
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned()),
        actor_type: actor_type(caller),
    }
}

/// The caller token's bound IdP identity, recorded on the change set so the
/// coordinator can refuse the same human approving their own plan.
pub(crate) fn owner_subject(
    caller: Option<&mecmcp_auth::CallerCtx<MistGrant>>,
) -> Option<mecmcp_changeset::OwnerSubject> {
    caller
        .and_then(|ctx| ctx.oidc_subject.as_ref())
        .map(|s| mecmcp_changeset::OwnerSubject {
            issuer: s.issuer.clone(),
            subject: s.subject.clone(),
        })
}

/// Format an object as a change-set `device` key.
///
/// `ChangeSetRecord.device` is what `device_guard` locks on, so it is the
/// concurrency unit. Mist has no devices, so the object being changed serves:
/// two operators editing different networks proceed in parallel, and two edits
/// to the same network serialize. A create has no UUID yet, so all creates of
/// one object type share a key and serialize — deliberate and cheap.
///
/// Objects that reference each other are deliberately NOT serialized against
/// each other. Widening this key to compensate would trade a real, understood
/// limitation for a coarse lock nobody can reason about.
#[allow(dead_code)]
pub(crate) fn object_key(object: WanObject, object_id: Option<&str>) -> String {
    let name = match object {
        WanObject::Network => "network",
        WanObject::Service => "service",
        WanObject::ServicePolicy => "servicepolicy",
        WanObject::GatewayTemplate => "gatewaytemplate",
        WanObject::DeviceProfile => "deviceprofile",
    };
    match object_id {
        Some(id) => format!("{name}/{id}"),
        None => format!("{name}/new"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_names_the_object_not_the_org() {
        assert_eq!(
            object_key(
                WanObject::Network,
                Some("2b0f0000-0000-0000-0000-000000000001")
            ),
            "network/2b0f0000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            object_key(WanObject::GatewayTemplate, Some("abc")),
            "gatewaytemplate/abc"
        );
    }

    #[test]
    fn creates_share_one_key_per_object_type() {
        assert_eq!(object_key(WanObject::Service, None), "service/new");
        assert_eq!(object_key(WanObject::Network, None), "network/new");
    }
}

/// A staged change set, ready to be recorded.
#[derive(Clone, Debug)]
pub(crate) struct StagedPlan {
    /// Change-set identifier.
    pub change_set_id: String,
    /// Digest binding owner, object, `before` fingerprint and the action.
    pub plan_digest: String,
    /// Digest over the exact body apply will send.
    pub preview_digest: String,
    /// The object as read, or `Value::Null` for a create.
    pub before: serde_json::Value,
    /// The merged body apply will send.
    pub after: serde_json::Value,
}

/// Stage a change set from owner, object, before state, and merged after.
///
/// Computes the change-set ID, fingerprint over `before`, plan digest, and
/// preview digest, builds the `ChangeSetRecord`, inserts it, and returns the
/// envelope. For a create, `before` must be `Value::Null`.
///
/// # Errors
///
/// Returns an error if the coordinator rejects the record.
#[allow(clippy::too_many_arguments)] // one call site; each argument is a distinct plan input
pub(crate) async fn stage_plan(
    coordinator: &Arc<mecmcp_changeset::ChangesetCoordinator>,
    owner: String,
    object: WanObject,
    object_id: Option<&str>,
    org_id: String,
    before: serde_json::Value,
    after: serde_json::Value,
    owner_subject: Option<mecmcp_changeset::OwnerSubject>,
) -> Result<StagedPlan, CoordinatorError> {
    // Compute fingerprint over the before state.
    let fingerprint = if before.is_null() {
        "create".to_owned()
    } else {
        let canonical = serde_json::to_vec(&before)
            .map_err(|error| CoordinatorError::new("before", error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    };

    // Generate change-set ID.
    let change_set_id = {
        let mut id_bytes = [0u8; 32];
        // getrandom 0.3 renamed `getrandom()` to `fill()`. Same system CSPRNG,
        // same error-on-partial-read contract — which matters here, because a
        // change-set id that is not unpredictable is a forgeable handle.
        getrandom::fill(&mut id_bytes)
            .map_err(|error| CoordinatorError::new("id", error.to_string()))?;
        hex::encode(id_bytes)
    };

    let device = object_key(object, object_id);
    let action = serde_json::json!({
        "object": match object {
            WanObject::Network => "network",
            WanObject::Service => "service",
            WanObject::ServicePolicy => "servicepolicy",
            WanObject::GatewayTemplate => "gatewaytemplate",
            WanObject::DeviceProfile => "deviceprofile",
        },
        "body": &after,
    });

    let plan_digest = digest::change_set_digest(&owner, &device, &fingerprint, &[&action])
        .map_err(|error| CoordinatorError::new("digest", error.to_string()))?;

    let preview_digest = {
        let preview_body = serde_json::to_string(&after)
            .map_err(|error| CoordinatorError::new("preview", error.to_string()))?;
        digest::preview_digest(&preview_body)
    };

    // Calculate expiration time (1 hour from now by default)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CoordinatorError::new("time", error.to_string()))?
        .as_secs();
    let expires_at_unix = now.saturating_add(3600);

    // Store before/after/org_id in preview for inspection and apply-time validation
    let preview_artifact = serde_json::json!({
        "before": &before,
        "after": &after,
        "org_id": &org_id,
    })
    .to_string();
    let preview_artifact_digest = digest::preview_digest(&preview_artifact);

    let record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: owner.clone(),
        owner_subject,
        device: device.clone(),
        expected_candidate_fingerprint: fingerprint.clone(),
        actions: vec![action],
        digest: plan_digest.clone(),
        state: ChangeSetState::Planned,
        approver: None,
        approval: None,
        expires_at_unix,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: Some(mecmcp_changeset::PreviewRecord {
            artifact: preview_artifact,
            digest: preview_artifact_digest,
            job_id: None,
        }),
        // Never an apply that lost its handle: this record is being created,
        // and a Mist write is synchronous with no handle to lose.
        apply_without_handle: false,
        // mecmcp 0.20.0 records a vendor task handle so an apply that dies
        // mid-flight leaves something to re-probe. Nothing is stored here: this
        // server's change sets do not start a long-running Mist operation, so
        // there is no handle to keep. The field is
        // `skip_serializing_if = "Option::is_none"`, so `None` never reaches the
        // state file and a previous binary can still read it.
        task_id: None,
    };

    coordinator.insert_change_set(record).await?;

    Ok(StagedPlan {
        change_set_id,
        plan_digest,
        preview_digest,
        before,
        after,
    })
}
