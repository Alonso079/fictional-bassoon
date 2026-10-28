use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use punishell_protocol::*;

fn now() -> DateTime<Utc> {
    "2026-10-11T12:00:00Z".parse().unwrap()
}

fn command() -> CommandClaims {
    CommandClaims {
        protocol_version: PROTOCOL_VERSION,
        command_id: "cmd-1".into(),
        tenant_id: "tenant-1".into(),
        agent_id: "agent-1".into(),
        issued_at: now(),
        expires_at: now() + Duration::minutes(5),
        nonce: "1234567890abcdef1234567890abcdef".into(),
        approval_id: None,
        action: Action::CollectInventory,
    }
}

#[test]
fn valid_signature_roundtrips_and_keys_are_independent() {
    let key = generate_signing_key();
    let another = generate_signing_key();
    assert_ne!(key.verifying_key(), another.verifying_key());
    let keys = BTreeMap::from([(
        "command-key".into(),
        TrustedKey {
            key: key.verifying_key(),
            not_before: now(),
            not_after: now() + Duration::days(1),
            revoked: false,
        },
    )]);
    let envelope = sign_command(&command(), "command-key", &key).unwrap();
    assert_eq!(
        verify_command_signature(&envelope, &keys, now()).unwrap(),
        command()
    );
}

#[test]
fn tampered_payload_is_rejected() {
    let key = generate_signing_key();
    let keys = BTreeMap::from([(
        "key".into(),
        TrustedKey {
            key: key.verifying_key(),
            not_before: now(),
            not_after: now() + Duration::days(1),
            revoked: false,
        },
    )]);
    let mut envelope = sign_command(&command(), "key", &key).unwrap();
    let mut changed = command();
    changed.agent_id = "victim".into();
    envelope.payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap());
    assert!(matches!(
        verify_command_signature(&envelope, &keys, now()),
        Err(ProtocolError::InvalidSignature)
    ));
}

#[test]
fn key_id_substitution_is_rejected_even_for_the_same_public_key() {
    let key = generate_signing_key();
    let make_trusted = || TrustedKey {
        key: key.verifying_key(),
        not_before: now(),
        not_after: now() + Duration::days(1),
        revoked: false,
    };
    let keys = BTreeMap::from([
        ("old".into(), make_trusted()),
        ("new".into(), make_trusted()),
    ]);
    let mut envelope = sign_command(&command(), "old", &key).unwrap();
    envelope.key_id = "new".into();
    assert!(matches!(
        verify_command_signature(&envelope, &keys, now()),
        Err(ProtocolError::InvalidSignature)
    ));
}

#[test]
fn unknown_revoked_and_expired_keys_are_rejected() {
    let key = generate_signing_key();
    let envelope = sign_command(&command(), "key", &key).unwrap();
    let mut keys = BTreeMap::new();
    assert!(matches!(
        verify_command_signature(&envelope, &keys, now()),
        Err(ProtocolError::UntrustedKey)
    ));
    keys.insert(
        "key".into(),
        TrustedKey {
            key: key.verifying_key(),
            not_before: now(),
            not_after: now() + Duration::days(1),
            revoked: true,
        },
    );
    assert!(matches!(
        verify_command_signature(&envelope, &keys, now()),
        Err(ProtocolError::UntrustedKey)
    ));
    keys.get_mut("key").unwrap().revoked = false;
    assert!(matches!(
        verify_command_signature(&envelope, &keys, now() - Duration::seconds(1)),
        Err(ProtocolError::UntrustedKey)
    ));
    assert!(matches!(
        verify_command_signature(&envelope, &keys, now() + Duration::days(1)),
        Err(ProtocolError::UntrustedKey)
    ));
}

#[test]
fn command_signature_cannot_be_used_as_license_signature() {
    let key = generate_signing_key();
    let keys = BTreeMap::from([(
        "key".into(),
        TrustedKey {
            key: key.verifying_key(),
            not_before: now(),
            not_after: now() + Duration::days(1),
            revoked: false,
        },
    )]);
    let envelope = sign_command(&command(), "key", &key).unwrap();
    assert!(matches!(
        verify_license_signature(&envelope, &keys, now()),
        Err(ProtocolError::InvalidSignature)
    ));
}

#[test]
fn unknown_actions_and_unknown_fields_are_not_accepted() {
    assert!(serde_json::from_str::<Action>(
        r#"{"type":"custom","parameters":{"command":"calc.exe"}}"#
    )
    .is_err());
    let mut value = serde_json::to_value(command()).unwrap();
    value["command_string"] = "calc.exe".into();
    assert!(serde_json::from_value::<CommandClaims>(value).is_err());
    assert!(
        serde_json::from_str::<Action>(r#"{"type":"collect_inventory","unexpected":1}"#).is_err()
    );
}

#[test]
fn oversized_and_malformed_envelopes_fail_before_parsing() {
    let mut command = command();
    command.command_id = "x".repeat(MAX_PAYLOAD_BYTES);
    let key = generate_signing_key();
    assert!(matches!(
        sign_command(&command, "key", &key),
        Err(ProtocolError::PayloadTooLarge)
    ));
    let envelope = SignedEnvelope {
        key_id: "key".into(),
        payload_b64: "!".into(),
        signature_b64: "wrong".into(),
    };
    assert!(matches!(
        verify_command_signature(&envelope, &BTreeMap::new(), now()),
        Err(ProtocolError::InvalidEncoding)
    ));
}

#[test]
fn signed_wire_format_has_a_stable_roundtrip() {
    let key = generate_signing_key();
    let envelope = sign_command(&command(), "key", &key).unwrap();
    let decoded: SignedEnvelope =
        serde_json::from_slice(&serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert_eq!(decoded, envelope);
}

#[test]
fn encrypted_transport_roundtrips_without_exposing_signed_payload() {
    let signing = generate_signing_key();
    let signed = sign_command(&command(), "command-key", &signing).unwrap();
    let key = [9u8; 32];
    let encrypted = encrypt_payload(
        &signed,
        EncryptionDirection::AgentToServer,
        "agent-1",
        "transport-1",
        &key,
    )
    .unwrap();
    let serialized = serde_json::to_string(&encrypted).unwrap();
    assert!(!serialized.contains("cmd-1"));
    let decrypted: SignedEnvelope = decrypt_payload(
        &encrypted,
        EncryptionDirection::AgentToServer,
        "agent-1",
        "transport-1",
        &key,
    )
    .unwrap();
    assert_eq!(decrypted, signed);
}

#[test]
fn encrypted_transport_authenticates_ciphertext_direction_and_context() {
    let key = [7u8; 32];
    let mut encrypted = encrypt_payload(
        &command(),
        EncryptionDirection::AgentToServer,
        "agent-1",
        "transport-1",
        &key,
    )
    .unwrap();
    assert!(decrypt_payload::<CommandClaims>(
        &encrypted,
        EncryptionDirection::ServerToAgent,
        "agent-1",
        "transport-1",
        &key,
    )
    .is_err());
    assert!(decrypt_payload::<CommandClaims>(
        &encrypted,
        EncryptionDirection::AgentToServer,
        "agent-2",
        "transport-1",
        &key,
    )
    .is_err());
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&encrypted.ciphertext_b64).unwrap();
    ciphertext[0] ^= 1;
    encrypted.ciphertext_b64 = URL_SAFE_NO_PAD.encode(ciphertext);
    assert!(decrypt_payload::<CommandClaims>(
        &encrypted,
        EncryptionDirection::AgentToServer,
        "agent-1",
        "transport-1",
        &key,
    )
    .is_err());
}

#[test]
fn bitlocker_contract_uses_explicit_non_secret_fields() {
    assert_eq!(
        serde_json::to_value(Feature::ManageBitLocker).unwrap(),
        "manage_bit_locker"
    );
    let action = Action::ResumeBitLockerProtection {
        mount_point: "C:".into(),
    };
    let value = serde_json::to_value(&action).unwrap();
    assert_eq!(value["type"], "resume_bit_locker_protection");
    assert_eq!(value["parameters"]["mount_point"], "C:");
    assert!(value.get("recovery_key").is_none());
}
