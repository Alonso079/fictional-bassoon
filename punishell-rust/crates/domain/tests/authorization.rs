use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use punishell_domain::*;
use punishell_protocol::*;

fn now() -> DateTime<Utc> {
    "2026-10-11T12:00:00Z".parse().unwrap()
}
fn command() -> CommandClaims {
    CommandClaims {
        protocol_version: PROTOCOL_VERSION,
        command_id: "command-1".into(),
        tenant_id: "tenant-1".into(),
        agent_id: "agent-1".into(),
        issued_at: now(),
        expires_at: now() + Duration::minutes(5),
        nonce: "0123456789abcdef0123456789abcdef".into(),
        approval_id: None,
        action: Action::CollectInventory,
    }
}
fn with_policy(f: impl FnOnce(&CommandPolicy<'_>)) {
    let features = BTreeSet::from([
        Feature::Inventory,
        Feature::LockWorkstation,
        Feature::Diagnostics,
        Feature::ManageServices,
        Feature::Updates,
        Feature::ManageBitLocker,
    ]);
    let services = BTreeSet::from(["PuniShellAgent".into()]);
    let channels = BTreeSet::from(["stable".into()]);
    f(&CommandPolicy {
        tenant_id: "tenant-1",
        agent_id: "agent-1",
        now: now(),
        enabled_features: &features,
        managed_services: &services,
        update_channels: &channels,
    });
}

#[test]
fn request_permission_requires_operator_in_the_same_tenant() {
    for role in [
        Role::Administrator,
        Role::Operator,
        Role::Approver,
        Role::Auditor,
    ] {
        let actor = Actor {
            user_id: "operator-1",
            tenant_id: "tenant-1",
            role,
            mfa_verified_at: None,
        };
        assert_eq!(
            authorize_request(&actor, "tenant-1").is_ok(),
            role == Role::Operator
        );
        assert!(authorize_request(&actor, "tenant-2").is_err());
    }
}

#[test]
fn approval_requires_a_different_user_fresh_mfa_and_pending_state() {
    let mut actor = Actor {
        user_id: "approver-1",
        tenant_id: "tenant-1",
        role: Role::Approver,
        mfa_verified_at: Some(now()),
    };
    assert!(authorize_approval(
        &actor,
        "tenant-1",
        "operator-1",
        CommandState::Pending,
        now()
    )
    .is_ok());
    assert!(matches!(
        authorize_approval(
            &actor,
            "tenant-1",
            "approver-1",
            CommandState::Pending,
            now()
        ),
        Err(DomainError::SelfApproval)
    ));
    assert!(authorize_approval(
        &actor,
        "tenant-1",
        "operator-1",
        CommandState::Approved,
        now()
    )
    .is_err());
    actor.mfa_verified_at = Some(now() - Duration::minutes(6));
    assert!(matches!(
        authorize_approval(
            &actor,
            "tenant-1",
            "operator-1",
            CommandState::Pending,
            now()
        ),
        Err(DomainError::MfaRequired)
    ));
    actor.mfa_verified_at = Some(now() + Duration::seconds(1));
    assert!(authorize_approval(
        &actor,
        "tenant-1",
        "operator-1",
        CommandState::Pending,
        now()
    )
    .is_err());
    actor.role = Role::Operator;
    actor.mfa_verified_at = Some(now());
    assert!(authorize_approval(
        &actor,
        "tenant-1",
        "operator-1",
        CommandState::Pending,
        now()
    )
    .is_err());
}

#[test]
fn command_lifecycle_rejects_skipped_steps_and_terminal_reentry() {
    use CommandState::*;
    for pair in [
        (Pending, Approved),
        (Approved, Claimed),
        (Claimed, Running),
        (Running, Succeeded),
    ] {
        assert_eq!(transition(pair.0, pair.1).unwrap(), pair.1);
    }
    assert!(transition(Pending, Running).is_err());
    assert!(transition(Approved, Succeeded).is_err());
    for state in [Succeeded, Failed, Rejected, Expired, Cancelled] {
        assert!(transition(state, Running).is_err());
    }
}

#[test]
fn complete_signed_validation_rejects_a_different_device() {
    with_policy(|policy| {
        let key = generate_signing_key();
        let keys = BTreeMap::from([(
            "server-key".into(),
            TrustedKey {
                key: key.verifying_key(),
                not_before: now(),
                not_after: now() + Duration::days(1),
                revoked: false,
            },
        )]);
        let envelope = sign_command(&command(), "server-key", &key).unwrap();
        assert!(validate_signed_command(&envelope, &keys, policy).is_ok());
        let mut changed = command();
        changed.agent_id = "agent-2".into();
        let envelope = sign_command(&changed, "server-key", &key).unwrap();
        assert!(matches!(
            validate_signed_command(&envelope, &keys, policy),
            Err(DomainError::InvalidCommand)
        ));
    });
}

#[test]
fn expired_future_overlong_wrong_tenant_and_invalid_nonce_commands_are_rejected() {
    with_policy(|policy| {
        let mut bad = command();
        bad.expires_at = now();
        assert!(validate_command(&bad, policy).is_err());
        bad = command();
        bad.issued_at += Duration::seconds(1);
        assert!(validate_command(&bad, policy).is_err());
        bad = command();
        bad.expires_at += Duration::seconds(1);
        assert!(validate_command(&bad, policy).is_err());
        bad = command();
        bad.tenant_id = "another".into();
        assert!(validate_command(&bad, policy).is_err());
        bad = command();
        bad.nonce = "short".into();
        assert!(validate_command(&bad, policy).is_err());
    });
}

#[test]
fn administrative_actions_require_approval_and_licensed_features() {
    with_policy(|policy| {
        let mut c = command();
        c.action = Action::LockWorkstation;
        assert!(matches!(
            validate_command(&c, policy),
            Err(DomainError::ApprovalRequired)
        ));
        c.approval_id = Some("approval-1".into());
        assert!(validate_command(&c, policy).is_ok());
        c.action = Action::RotateAgentKey;
        assert!(matches!(
            validate_command(&c, policy),
            Err(DomainError::Forbidden)
        ));
    });
}

#[test]
fn parameters_cannot_expand_service_scope_or_resource_limits() {
    with_policy(|policy| {
        let mut c = command();
        c.approval_id = Some("approval-1".into());
        c.action = Action::RestartManagedService {
            service_name: "PuniShellAgent".into(),
        };
        assert!(validate_command(&c, policy).is_ok());
        c.action = Action::RestartManagedService {
            service_name: "WinDefend".into(),
        };
        assert!(validate_command(&c, policy).is_err());
        c.action = Action::RequestUpdate {
            channel: "untrusted".into(),
        };
        assert!(validate_command(&c, policy).is_err());
        c.action = Action::DiagnosticBundle {
            max_bytes: 1_048_577,
            timeout_seconds: 60,
        };
        assert!(validate_command(&c, policy).is_err());
        c.action = Action::DiagnosticBundle {
            max_bytes: 512,
            timeout_seconds: 61,
        };
        assert!(validate_command(&c, policy).is_err());
        c.action = Action::ResumeBitLockerProtection {
            mount_point: "C:".into(),
        };
        assert!(validate_command(&c, policy).is_ok());
        c.action = Action::ResumeBitLockerProtection {
            mount_point: "c:".into(),
        };
        assert!(validate_command(&c, policy).is_err());
        c.action = Action::ResumeBitLockerProtection {
            mount_point: "C:\\Windows".into(),
        };
        assert!(validate_command(&c, policy).is_err());
    });
}
