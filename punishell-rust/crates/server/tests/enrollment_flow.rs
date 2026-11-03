use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use punishell_protocol::{
    decrypt_payload, encrypt_payload, generate_signing_key, sign_license, sign_payload,
    verify_payload, wire::*, AgentWireEnvelope, EncryptionDirection, Feature, LicenseClaims,
    Purpose, SignedEnvelope, TrustStore, TrustedKey, PRODUCT, PROTOCOL_VERSION,
};
use punishell_server::{
    api, security,
    store::{write_private, App, Config, LICENSE_KEY, SERVER_KEY},
};
use sqlx::Row;
use std::{collections::BTreeSet, path::PathBuf};
use tower::ServiceExt;

async fn post<T: serde::Serialize>(
    router: &Router,
    path: &str,
    value: &T,
) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("x-punishell-transport", "aes256gcm-v1")
        .body(Body::from(serde_json::to_vec(value).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
}
async fn fixture_with_provider() -> (
    tempfile::TempDir,
    std::sync::Arc<App>,
    Router,
    ed25519_dalek::SigningKey,
) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    for name in ["command", "server", "update", "encryption"] {
        write_private(
            &state.join(format!("{name}.key")),
            &generate_signing_key().to_bytes(),
        )
        .unwrap();
    }
    let provider_key = generate_signing_key();
    write_private(
        &state.join("trust.json"),
        &serde_json::to_vec(&serde_json::json!({
            "license": punishell_server::store::public_config(LICENSE_KEY, &provider_key)
        }))
        .unwrap(),
    )
    .unwrap();
    let config = Config {
        state_dir: state,
        bind: "127.0.0.1:0".into(),
        public_url: "https://localhost".into(),
        tls_certificate: PathBuf::new(),
        tls_private_key: PathBuf::new(),
        managed_services: BTreeSet::new(),
        update_channels: BTreeSet::new(),
    };
    let app = App::open(config).await.unwrap();
    sqlx::query("INSERT INTO tenants VALUES('main','Main',?)")
        .bind(Utc::now().timestamp())
        .execute(&app.pool)
        .await
        .unwrap();
    let now = Utc::now();
    let license = LicenseClaims {
        protocol_version: PROTOCOL_VERSION,
        license_id: security::id(),
        tenant_id: "main".into(),
        product: PRODUCT.into(),
        plan: "six_months".into(),
        features: BTreeSet::from([Feature::Inventory]),
        max_agents: 1,
        issued_at: now,
        expires_at: now + Duration::days(180),
        offline_grace_hours: 24,
    };
    let signed = sign_license(&license, LICENSE_KEY, &provider_key).unwrap();
    sqlx::query("INSERT INTO licenses(id,tenant_id,envelope,issued_at) VALUES(?,'main',?,?)")
        .bind(&license.license_id)
        .bind(serde_json::to_string(&signed).unwrap())
        .bind(now.timestamp())
        .execute(&app.pool)
        .await
        .unwrap();
    let router = api::router(app.clone());
    (dir, app, router, provider_key)
}
async fn fixture() -> (tempfile::TempDir, std::sync::Arc<App>, Router) {
    let (dir, app, router, _) = fixture_with_provider().await;
    (dir, app, router)
}
#[tokio::test]
async fn enrollment_signed_heartbeat_and_replay() {
    let (_dir, app, router) = fixture().await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ready: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(
        ready["schema_version"],
        punishell_server::store::SCHEMA_VERSION
    );
    let code = security::token();
    sqlx::query("INSERT INTO activation_codes(code_hash,tenant_id,expires_at) VALUES(?,'main',?)")
        .bind(security::digest(code.as_bytes()))
        .bind((Utc::now() + Duration::minutes(5)).timestamp())
        .execute(&app.pool)
        .await
        .unwrap();
    let key = generate_signing_key();
    let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let (status, bytes) = post(
        &router,
        "/api/v1/enrollment/start",
        &EnrollmentStart {
            tenant_id: "main".into(),
            activation_code: code.clone(),
            public_key_b64: public.clone(),
        },
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let envelope: SignedEnvelope = serde_json::from_slice(&bytes).unwrap();
    let mut trust = TrustStore::new();
    trust.insert(
        SERVER_KEY.into(),
        TrustedKey {
            key: app.server_key.verifying_key(),
            not_before: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            not_after: chrono::DateTime::from_timestamp(4_102_444_800, 0).unwrap(),
            revoked: false,
        },
    );
    let challenge: EnrollmentChallenge =
        verify_payload(&envelope, Purpose::Server, &trust, Utc::now()).unwrap();
    assert_eq!(challenge.public_key_b64, public);
    let request = DeviceRequest {
        agent_id: challenge.agent_id.clone(),
        request_id: security::id(),
        sequence: 1,
        issued_at: Utc::now(),
        operation: AgentOperation::Enroll {
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
        },
    };
    let envelope = sign_payload(&request, Purpose::Device, &challenge.agent_id, &key).unwrap();
    let (status, bytes) = post(&router, "/api/v1/agent", &envelope).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let reply: SignedEnvelope = serde_json::from_slice(&bytes).unwrap();
    let message: ServerMessage =
        verify_payload(&reply, Purpose::Server, &trust, Utc::now()).unwrap();
    assert_eq!(message.request_id, request.request_id);
    let transport_id = message.transport_key_id.clone().unwrap();
    let transport_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(message.transport_key_b64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let stored_transport: String =
        sqlx::query_scalar("SELECT transport_key FROM agents WHERE id=?")
            .bind(&challenge.agent_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let stored_receipt: String =
        sqlx::query_scalar("SELECT response FROM receipts WHERE agent_id=? AND request_id=?")
            .bind(&challenge.agent_id)
            .bind(&request.request_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(!stored_transport.contains(message.transport_key_b64.as_ref().unwrap()));
    assert!(!stored_receipt.contains(message.transport_key_b64.as_ref().unwrap()));
    let (status, retry) = post(&router, "/api/v1/agent", &envelope).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, retry);
    let stale = sign_payload(
        &ServerMessage {
            request_id: request.request_id.clone(),
            agent_id: challenge.agent_id.clone(),
            issued_at: Utc::now() - Duration::minutes(5),
            expires_at: Utc::now() - Duration::minutes(3),
            revoked: false,
            license: message.license,
            command: None,
            lease_token: None,
            transport_key_id: None,
            transport_key_b64: None,
        },
        Purpose::Server,
        SERVER_KEY,
        &app.server_key,
    )
    .unwrap();
    sqlx::query("UPDATE receipts SET response=? WHERE agent_id=? AND request_id=?")
        .bind(serde_json::to_string(&stale).unwrap())
        .bind(&challenge.agent_id)
        .bind(&request.request_id)
        .execute(&app.pool)
        .await
        .unwrap();
    let (status, refreshed) = post(&router, "/api/v1/agent", &envelope).await;
    assert_eq!(status, StatusCode::OK);
    let verified: ServerMessage = verify_payload(
        &serde_json::from_slice::<SignedEnvelope>(&refreshed).unwrap(),
        Purpose::Server,
        &trust,
        Utc::now(),
    )
    .unwrap();
    assert!(verified.expires_at > Utc::now());
    let heartbeat = DeviceRequest {
        agent_id: challenge.agent_id.clone(),
        request_id: security::id(),
        sequence: 2,
        issued_at: Utc::now(),
        operation: AgentOperation::Heartbeat {
            inventory: Inventory {
                hostname: Some("test-win".into()),
                bitlocker_volumes: vec![BitLockerVolume {
                    mount_point: Some("C:".into()),
                    protection_status: "on".into(),
                    conversion_status: Some("fully_encrypted".into()),
                    encryption_percentage: Some(100),
                    encryption_method: Some("xts_aes_256".into()),
                    lock_status: Some("unlocked".into()),
                    auto_unlock_enabled: Some(false),
                    errors: vec![],
                }],
                ..Inventory::default()
            },
            version: "0.1.0".into(),
        },
    };
    let signed = sign_payload(&heartbeat, Purpose::Device, &challenge.agent_id, &key).unwrap();
    let protected = encrypt_payload(
        &signed,
        EncryptionDirection::AgentToServer,
        &challenge.agent_id,
        &transport_id,
        &transport_key,
    )
    .unwrap();
    let (status, bytes) = post(&router, "/api/v1/agent", &protected).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let protected_reply: AgentWireEnvelope = serde_json::from_slice(&bytes).unwrap();
    let AgentWireEnvelope::Encrypted(protected_reply) = protected_reply else {
        panic!("el servidor debe responder cifrado")
    };
    let signed_reply: SignedEnvelope = decrypt_payload(
        &protected_reply,
        EncryptionDirection::ServerToAgent,
        &challenge.agent_id,
        &transport_id,
        &transport_key,
    )
    .unwrap();
    let heartbeat_reply: ServerMessage =
        verify_payload(&signed_reply, Purpose::Server, &trust, Utc::now()).unwrap();
    assert_eq!(heartbeat_reply.request_id, heartbeat.request_id);
    let stored: String = sqlx::query("SELECT inventory FROM agents WHERE id=?")
        .bind(&challenge.agent_id)
        .fetch_one(&app.pool)
        .await
        .unwrap()
        .get("inventory");
    assert!(stored.contains("test-win"));
    let sample = sqlx::query(
        "SELECT uptime_millis,error_count,version,bitlocker_protected_count,bitlocker_unprotected_count FROM telemetry_samples WHERE agent_id=?",
    )
    .bind(&challenge.agent_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(sample.get::<i64, _>("uptime_millis"), 0);
    assert_eq!(sample.get::<i64, _>("error_count"), 0);
    assert_eq!(sample.get::<String, _>("version"), "0.1.0");
    assert_eq!(sample.get::<i64, _>("bitlocker_protected_count"), 1);
    assert_eq!(sample.get::<i64, _>("bitlocker_unprotected_count"), 0);
    let replay = DeviceRequest {
        agent_id: challenge.agent_id.clone(),
        request_id: security::id(),
        sequence: 2,
        issued_at: Utc::now(),
        operation: AgentOperation::Heartbeat {
            inventory: Inventory::default(),
            version: "0.1.0".into(),
        },
    };
    let replay = sign_payload(&replay, Purpose::Device, &challenge.agent_id, &key).unwrap();
    let replay = encrypt_payload(
        &replay,
        EncryptionDirection::AgentToServer,
        &challenge.agent_id,
        &transport_id,
        &transport_key,
    )
    .unwrap();
    let (status, _) = post(&router, "/api/v1/agent", &replay).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let consumed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM activation_codes WHERE used_at IS NOT NULL")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(consumed, 1);
    let (status, _) = post(
        &router,
        "/api/v1/enrollment/start",
        &EnrollmentStart {
            tenant_id: "main".into(),
            activation_code: code,
            public_key_b64: public,
        },
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Maintenance must not prevent a legitimate late result from resolving
    // an action already claimed before its execution window expired.
    sqlx::query("INSERT INTO users(id,tenant_id,username,password_hash,role,totp_secret) VALUES('operator','main','operator','unused','requester','unused')")
        .execute(&app.pool).await.unwrap();
    sqlx::query("INSERT INTO commands(id,tenant_id,agent_id,requester,action,state,created_at,expires_at,lease_token) VALUES('late','main',?,'operator',?,'claimed',0,1,'valid-lease')")
        .bind(&challenge.agent_id)
        .bind(serde_json::to_string(&punishell_protocol::Action::ResumeBitLockerProtection { mount_point: "C:".into() }).unwrap())
        .execute(&app.pool).await.unwrap();
    assert_eq!(
        app.maintain(Utc::now().timestamp())
            .await
            .unwrap()
            .expired_commands,
        1
    );
    for (lease, expected) in [
        ("wrong-lease", StatusCode::FORBIDDEN),
        ("valid-lease", StatusCode::OK),
    ] {
        let complete = DeviceRequest {
            agent_id: challenge.agent_id.clone(),
            request_id: security::id(),
            sequence: 3,
            issued_at: Utc::now(),
            operation: AgentOperation::Complete {
                command_id: "late".into(),
                lease_token: lease.into(),
                success: true,
                output: "completed before disconnect".into(),
            },
        };
        let signed = sign_payload(&complete, Purpose::Device, &challenge.agent_id, &key).unwrap();
        let encrypted = encrypt_payload(
            &signed,
            EncryptionDirection::AgentToServer,
            &challenge.agent_id,
            &transport_id,
            &transport_key,
        )
        .unwrap();
        assert_eq!(post(&router, "/api/v1/agent", &encrypted).await.0, expected);
    }
    let state: String = sqlx::query_scalar("SELECT state FROM commands WHERE id='late'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(state, "succeeded");
    let verification: String =
        sqlx::query_scalar("SELECT verification_state FROM commands WHERE id='late'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(verification, "pending"); // Stored pre-execution C: inventory was on.
    for (sequence, mount_point, expected) in [(4, "D:", "pending"), (5, "C:", "verified")] {
        let request = DeviceRequest {
            agent_id: challenge.agent_id.clone(),
            request_id: security::id(),
            sequence,
            issued_at: Utc::now(),
            operation: AgentOperation::Heartbeat {
                inventory: Inventory {
                    bitlocker_volumes: vec![test_volume(mount_point, "on")],
                    ..Default::default()
                },
                version: "0.1.0".into(),
            },
        };
        let signed = sign_payload(&request, Purpose::Device, &challenge.agent_id, &key).unwrap();
        let encrypted = encrypt_payload(
            &signed,
            EncryptionDirection::AgentToServer,
            &challenge.agent_id,
            &transport_id,
            &transport_key,
        )
        .unwrap();
        let (status, _) = post(&router, "/api/v1/agent", &encrypted).await;
        assert_eq!(status, StatusCode::OK);
        let verification: String =
            sqlx::query_scalar("SELECT verification_state FROM commands WHERE id='late'")
                .fetch_one(&app.pool)
                .await
                .unwrap();
        assert_eq!(verification, expected);
        // A byte-identical replay must not duplicate verification audit events.
        assert_eq!(
            post(&router, "/api/v1/agent", &encrypted).await.0,
            StatusCode::OK
        );
    }
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event='command_verified'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(events, 1);
    let token = security::token();
    sqlx::query("INSERT INTO sessions VALUES(?,'operator','csrf',?,0)")
        .bind(security::digest(token.as_bytes()))
        .bind(Utc::now().timestamp() + 3600)
        .execute(&app.pool)
        .await
        .unwrap();
    for path in [
        "/api/v1/commands".to_string(),
        format!("/api/v1/agents/{}", challenge.agent_id),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("cookie", format!("punishell={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        let commands = data
            .as_array()
            .or_else(|| data["commands"].as_array())
            .unwrap();
        assert_eq!(
            commands.iter().find(|c| c["id"] == "late").unwrap()["verification"]["state"],
            "verified"
        );
    }
}

fn test_volume(mount_point: &str, status: &str) -> BitLockerVolume {
    BitLockerVolume {
        mount_point: Some(mount_point.into()),
        protection_status: status.into(),
        conversion_status: None,
        encryption_percentage: Some(100),
        encryption_method: None,
        lock_status: None,
        auto_unlock_enabled: None,
        errors: vec![],
    }
}

#[tokio::test]
async fn administrator_login_imports_provider_license_and_technical_operator_activates() {
    let (_dir, app, router, provider) = fixture_with_provider().await;
    let created = api::add_user(
        &app,
        "main",
        "owner",
        "una-contrasena-segura-para-prueba",
        "platform_administrator",
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap();
    let encrypted: String = sqlx::query_scalar("SELECT totp_secret FROM users WHERE id=?")
        .bind(id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    let secret = security::decrypt(&app.encryption_key, id, &encrypted).unwrap();
    let code = security::totp(&secret)
        .unwrap()
        .generate(Utc::now().timestamp() as u64);
    let request=Request::builder().method("POST").uri("/api/v1/login").header("content-type","application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({"username":"owner","password":"una-contrasena-segura-para-prueba","totp":code})).unwrap())).unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let login: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let csrf = login["csrf"].as_str().unwrap();
    let overview_request = Request::builder()
        .method("GET")
        .uri("/api/v1/overview")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(overview_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let overview: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(overview["agents"]["total"], 0);
    assert_eq!(overview["telemetry_samples_24h"], 0);
    let start = Utc::now();
    let claims = LicenseClaims {
        protocol_version: PROTOCOL_VERSION,
        license_id: "renewal".into(),
        tenant_id: "main".into(),
        product: PRODUCT.into(),
        plan: "business".into(),
        features: BTreeSet::from([Feature::Inventory]),
        max_agents: 25,
        issued_at: start,
        expires_at: punishell_licensing::subscription_expires_at(start, 6).unwrap(),
        offline_grace_hours: 72,
    };
    sqlx::query("UPDATE licenses SET issued_at=issued_at-1")
        .execute(&app.pool)
        .await
        .unwrap();
    let envelope = sign_license(&claims, LICENSE_KEY, &provider).unwrap();
    let license_request = Request::builder()
        .method("POST")
        .uri("/api/v1/licenses/import")
        .header("content-type", "application/json")
        .header("cookie", &cookie)
        .header("x-csrf-token", csrf)
        .body(Body::from(serde_json::to_vec(&envelope).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(license_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issued: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(issued["claims"]["max_agents"], 25);
    let denied = Request::builder()
        .method("POST")
        .uri("/api/v1/activation-codes")
        .header("content-type", "application/json")
        .header("cookie", &cookie)
        .header("x-csrf-token", csrf)
        .body(Body::from(r#"{"ttl_minutes":15}"#))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(denied).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE users SET role='technical_operator' WHERE id=?")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    let code_request = Request::builder()
        .method("POST")
        .uri("/api/v1/activation-codes")
        .header("content-type", "application/json")
        .header("cookie", &cookie)
        .header("x-csrf-token", csrf)
        .body(Body::from(r#"{"ttl_minutes":15}"#))
        .unwrap();
    let response = router.clone().oneshot(code_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(body["activation_code"].as_str().unwrap().len(), 43);
}

#[tokio::test]
async fn maintenance_expires_offline_commands_and_preserves_live_data() {
    let (_dir, app, _router) = fixture().await;
    let now = 2_000_000_000;
    // Explicit timestamps exercise expiration boundaries without sleeping.
    sqlx::raw_sql(
        "INSERT INTO users(id,tenant_id,username,password_hash,role,totp_secret)
         VALUES('operator','main','operator','unused','requester','unused');
         INSERT INTO agents(id,tenant_id,public_key,sequence) VALUES('offline','main','unused',17);
         INSERT INTO sessions VALUES('expired','operator','csrf',2000000000,0),('live','operator','csrf',2000000001,0);
         INSERT INTO password_resets VALUES('expired','operator',2000000000,NULL),('live','operator',2000000001,NULL);
         INSERT INTO activation_codes(code_hash,tenant_id,expires_at) VALUES
         ('expired','main',2000000000),('referenced','main',2000000000),('live','main',2000000001);
         INSERT INTO challenges VALUES
         ('expired','main','offline','expired','unused','nonce',2000000000,NULL),
         ('live','main','offline','referenced','unused','nonce',2000000001,NULL);
         INSERT INTO rate_limits VALUES('old',1999913599,100),('boundary',1999913600,100),('live',2000000000,100);
         INSERT INTO receipts VALUES('offline','receipt','hash','encrypted-response',0);
         INSERT INTO commands(id,tenant_id,agent_id,requester,action,state,created_at,expires_at,lease_token) VALUES
         ('pending','main','offline','operator','{}','pending',0,2000000000,NULL),
         ('approved','main','offline','operator','{}','approved',0,2000000000,NULL),
         ('claimed','main','offline','operator','{}','claimed',0,2000000000,'lease'),
         ('live','main','offline','operator','{}','approved',0,2000000001,NULL),
         ('done','main','offline','operator','{}','succeeded',0,2000000000,NULL);
         INSERT INTO telemetry_samples(tenant_id,agent_id,captured_at,version,uptime_millis,adapter_count,wifi_count,interactive_user_count,error_count) VALUES
         ('main','offline',1997407999,'0.1.0',0,0,0,0,0),
         ('main','offline',1997408000,'0.1.0',0,0,0,0,0);",
    ).execute(&app.pool).await.unwrap();
    let report = app.maintain(now).await.unwrap();
    assert_eq!(report.expired_commands, 3);
    assert_eq!(report.sessions, 1);
    assert_eq!(report.challenges, 1);
    assert_eq!(report.activation_codes, 1);
    assert_eq!(report.password_resets, 1);
    assert_eq!(report.rate_limits, 1);
    assert_eq!(report.telemetry_samples, 1);
    let states: Vec<(String, String)> = sqlx::query_as("SELECT id,state FROM commands ORDER BY id")
        .fetch_all(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        states,
        vec![
            ("approved".into(), "expired".into()),
            ("claimed".into(), "expired".into()),
            ("done".into(), "succeeded".into()),
            ("live".into(), "approved".into()),
            ("pending".into(), "expired".into()),
        ]
    );
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event='command_expired'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(events, 3);
    let retained: (i64, i64, String) = sqlx::query_as(
        "SELECT sequence,(SELECT COUNT(*) FROM receipts),lease_token FROM agents JOIN commands ON commands.agent_id=agents.id WHERE commands.id='claimed'",
    ).fetch_one(&app.pool).await.unwrap();
    assert_eq!(retained, (17, 1, "lease".into()));
    assert_eq!(
        app.maintain(now).await.unwrap(),
        punishell_server::store::MaintenanceReport {
            at: now,
            ..Default::default()
        }
    );
    // A late receipt for a claimed action can still resolve an expired command;
    // expiry does not invent a successful or failed OS result.
    let unfinished: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM commands WHERE state='expired' AND completed_at IS NOT NULL",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(unfinished, 0);
}

#[tokio::test]
async fn maintenance_rolls_back_expiry_when_audit_fails() {
    let (_dir, app, _router) = fixture().await;
    sqlx::raw_sql(
        "INSERT INTO users(id,tenant_id,username,password_hash,role,totp_secret)
         VALUES('operator','main','operator','unused','requester','unused');
         INSERT INTO agents(id,tenant_id,public_key) VALUES('offline','main','unused');
         INSERT INTO commands(id,tenant_id,agent_id,requester,action,state,created_at,expires_at)
         VALUES('pending','main','offline','operator','{}','pending',0,1);
         CREATE TRIGGER reject_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test failure'); END;",
    ).execute(&app.pool).await.unwrap();
    assert!(app.maintain(2).await.is_err());
    let state: String = sqlx::query_scalar("SELECT state FROM commands WHERE id='pending'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(state, "pending");
}

#[tokio::test]
async fn readiness_returns_unavailable_for_invalid_schema_and_database_failure() {
    let (_dir, app, router) = fixture().await;
    sqlx::query("INSERT INTO schema_version VALUES(99)")
        .execute(&app.pool)
        .await
        .unwrap();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(body, serde_json::json!({"status":"not_ready"}));
    app.pool.close().await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn readiness_has_a_bounded_wait_when_database_is_busy() {
    let (_dir, app, router) = fixture().await;
    let _connection = app.pool.acquire().await.unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        router.oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("readiness must not hang")
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

async fn incident_inventory(app: &App, seen: i64, inventory: &Inventory) {
    sqlx::query("UPDATE agents SET last_seen=?,inventory=? WHERE id='monitored'")
        .bind(seen)
        .bind(serde_json::to_string(inventory).unwrap())
        .execute(&app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn incidents_deduplicate_require_fresh_recovery_and_reopen() {
    let (_dir, app, _router) = fixture().await;
    let now = Utc::now().timestamp();
    sqlx::query("INSERT INTO agents(id,tenant_id,public_key) VALUES('monitored','main','unused')")
        .execute(&app.pool)
        .await
        .unwrap();
    let mut inventory = Inventory {
        disk_free_bytes: Some(5),
        disk_total_bytes: Some(100),
        bitlocker_volumes: vec![BitLockerVolume {
            mount_point: Some("C:".into()),
            protection_status: "off".into(),
            conversion_status: None,
            encryption_percentage: Some(100),
            encryption_method: None,
            lock_status: None,
            auto_unlock_enabled: None,
            errors: vec![],
        }],
        ..Default::default()
    };
    incident_inventory(&app, now, &inventory).await;
    app.maintain(now).await.unwrap();
    app.maintain(now + 1).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    // Preserve recognition while the same finding remains active.
    sqlx::query("UPDATE incidents SET state='acknowledged' WHERE kind='disk_low'")
        .execute(&app.pool)
        .await
        .unwrap();
    app.maintain(now + 2).await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM incidents WHERE kind='disk_low'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(state, "acknowledged");
    inventory.disk_free_bytes = Some(90);
    inventory.bitlocker_volumes[0].protection_status = "on".into();
    // Even a healthy-looking old inventory cannot close either finding.
    incident_inventory(&app, now, &inventory).await;
    app.maintain(now + 3).await.unwrap();
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE state!='resolved'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(active, 2); // Same evidence timestamp cannot establish recovery.
    app.maintain(now + 901).await.unwrap();
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE state!='resolved'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(active, 3); // Includes the newly detected offline incident.
                           // Unknown BitLocker data after reconnect is not proof of protection.
    inventory.bitlocker_volumes[0].protection_status = "unknown".into();
    incident_inventory(&app, now + 902, &inventory).await;
    app.maintain(now + 902).await.unwrap();
    let active: Vec<String> =
        sqlx::query_scalar("SELECT kind FROM incidents WHERE state!='resolved'")
            .fetch_all(&app.pool)
            .await
            .unwrap();
    assert_eq!(active, vec!["bitlocker_unprotected"]);
    inventory.bitlocker_volumes[0].protection_status = "on".into();
    incident_inventory(&app, now + 903, &inventory).await;
    app.maintain(now + 903).await.unwrap();
    inventory.bitlocker_volumes[0].protection_status = "off".into();
    incident_inventory(&app, now + 904, &inventory).await;
    app.maintain(now + 904).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE kind='bitlocker_unprotected'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(count, 2); // New episode; the previous history is retained.
    sqlx::query("UPDATE agents SET revoked=1 WHERE id='monitored'")
        .execute(&app.pool)
        .await
        .unwrap();
    app.maintain(now + 905).await.unwrap();
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE state!='resolved'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(active, 0);
    let closed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event='incident_closed_revoked'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(closed, 1);
}

#[tokio::test]
async fn incident_api_enforces_tenant_roles_csrf_and_audits_acknowledgement() {
    let (_dir, app, router) = fixture().await;
    let now = Utc::now().timestamp();
    sqlx::raw_sql(
        "INSERT INTO tenants VALUES('other','Other',0);
        INSERT INTO agents(id,tenant_id,public_key) VALUES('monitored','main','unused');
        INSERT INTO users(id,tenant_id,username,password_hash,role,totp_secret) VALUES
        ('operator','main','operator','unused','technical_operator','unused'),
        ('auditor','main','auditor','unused','auditor','unused'),
        ('foreign','other','foreign','unused','technical_operator','unused');",
    )
    .execute(&app.pool)
    .await
    .unwrap();
    incident_inventory(&app, now - 901, &Inventory::default()).await;
    app.maintain(now).await.unwrap();
    let id: String = sqlx::query_scalar("SELECT id FROM incidents")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    let mut tokens = vec![];
    for user in ["operator", "auditor", "foreign"] {
        let token = security::token();
        sqlx::query("INSERT INTO sessions VALUES(?,?,'csrf',?,?)")
            .bind(security::digest(token.as_bytes()))
            .bind(user)
            .bind(now + 3600)
            .bind(now)
            .execute(&app.pool)
            .await
            .unwrap();
        tokens.push(token);
    }
    for (token, csrf, expected) in [
        ("invalid", "csrf", StatusCode::UNAUTHORIZED),
        (tokens[0].as_str(), "wrong", StatusCode::FORBIDDEN),
        (tokens[1].as_str(), "csrf", StatusCode::FORBIDDEN),
        (tokens[2].as_str(), "csrf", StatusCode::CONFLICT),
        (tokens[0].as_str(), "csrf", StatusCode::OK),
        (tokens[0].as_str(), "csrf", StatusCode::CONFLICT),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/incidents/{id}/acknowledge"))
            .header("cookie", format!("punishell={token}"))
            .header("x-csrf-token", csrf)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
    for (token, expected) in [(&tokens[0], 1), (&tokens[2], 0)] {
        let request = Request::builder()
            .uri("/api/v1/incidents")
            .header("cookie", format!("punishell={token}"))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let records: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(records.as_array().unwrap().len(), expected);
    }
    let audit: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event='incident_acknowledged'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(audit, 1);
}

#[tokio::test]
async fn existing_v4_database_migrates_without_losing_agents() {
    let (_dir, app, _router) = fixture().await;
    sqlx::raw_sql("INSERT INTO agents(id,tenant_id,public_key,sequence) VALUES('existing','main','unused',42);
        DROP TABLE incidents;
        DROP INDEX commands_verification;
        ALTER TABLE commands DROP COLUMN verification_state;
        ALTER TABLE commands DROP COLUMN verification_sequence;
        ALTER TABLE commands DROP COLUMN verification_deadline;
        ALTER TABLE commands DROP COLUMN verification_at;
        ALTER TABLE commands DROP COLUMN verification_detail;
        ALTER TABLE commands DROP COLUMN verification_last_status;
        DELETE FROM schema_version WHERE version>=5;")
        .execute(&app.pool).await.unwrap();
    let config = app.config.clone();
    app.pool.close().await;
    let upgraded = App::open(config.clone()).await.unwrap();
    let sequence: i64 = sqlx::query_scalar("SELECT sequence FROM agents WHERE id='existing'")
        .fetch_one(&upgraded.pool)
        .await
        .unwrap();
    assert_eq!(sequence, 42);
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&upgraded.pool)
        .await
        .unwrap();
    assert_eq!(version, punishell_server::store::SCHEMA_VERSION);
    upgraded.maintain(Utc::now().timestamp()).await.unwrap();
    upgraded.pool.close().await;
    // Reopening must not reapply the migration.
    App::open(config).await.unwrap().pool.close().await;
}

#[tokio::test]
async fn incident_opening_rolls_back_when_audit_is_unavailable() {
    let (_dir, app, _router) = fixture().await;
    let now = Utc::now().timestamp();
    sqlx::query("INSERT INTO agents(id,tenant_id,public_key,last_seen) VALUES('monitored','main','unused',?)")
        .bind(now - 901).execute(&app.pool).await.unwrap();
    sqlx::raw_sql("CREATE TRIGGER reject_incident_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test failure'); END;")
        .execute(&app.pool).await.unwrap();
    assert!(app.maintain(now).await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn bitlocker_verification_rejects_ambiguous_evidence_and_closes_on_deadline() {
    use punishell_server::verification;
    let (_dir, app, _router) = fixture().await;
    let now = Utc::now().timestamp();
    sqlx::raw_sql("INSERT INTO agents(id,tenant_id,public_key) VALUES('device','main','unused'),('other','main','unused');
        INSERT INTO users(id,tenant_id,username,password_hash,role,totp_secret) VALUES('operator','main','operator','unused','requester','unused');")
        .execute(&app.pool).await.unwrap();
    for id in ["off", "unknown", "revoked"] {
        sqlx::query("INSERT INTO commands(id,tenant_id,agent_id,requester,action,state,created_at,expires_at) VALUES(?,'main',?,'operator',?,'succeeded',0,1)")
            .bind(id).bind(if id=="revoked" {"other"}else{"device"})
            .bind(serde_json::to_string(&punishell_protocol::Action::ResumeBitLockerProtection {mount_point:"C:".into()}).unwrap())
            .execute(&app.pool).await.unwrap();
        let mut tx = app.pool.begin().await.unwrap();
        verification::start(&mut tx, id, 10, now).await.unwrap();
        tx.commit().await.unwrap();
    }
    let on = test_volume("C:", "on");
    let mut error = on.clone();
    error.errors.push("WMI incompleto".into());
    for volumes in [
        vec![],
        vec![error],
        vec![on.clone(), on.clone()],
        vec![test_volume("D:", "on")],
    ] {
        let mut tx = app.pool.begin().await.unwrap();
        verification::observe(
            &mut tx,
            "device",
            &Inventory {
                bitlocker_volumes: volumes,
                ..Default::default()
            },
            11,
            now + 1,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // A healthy reading with a pre-completion sequence cannot verify anything.
    let mut tx = app.pool.begin().await.unwrap();
    verification::observe(
        &mut tx,
        "device",
        &Inventory {
            bitlocker_volumes: vec![on.clone()],
            ..Default::default()
        },
        10,
        now + 2,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let states: Vec<String> = sqlx::query_scalar("SELECT verification_state FROM commands")
        .fetch_all(&app.pool)
        .await
        .unwrap();
    assert!(states.iter().all(|s| s == "pending"));
    // Off evidence is retained until the verification window ends.
    let mut tx = app.pool.begin().await.unwrap();
    verification::observe(
        &mut tx,
        "device",
        &Inventory {
            bitlocker_volumes: vec![test_volume("C:", "off")],
            ..Default::default()
        },
        12,
        now + 3,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE commands SET verification_last_status='unknown' WHERE id='unknown'")
        .execute(&app.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE agents SET revoked=1 WHERE id='other'")
        .execute(&app.pool)
        .await
        .unwrap();
    let mut tx = app.pool.begin().await.unwrap();
    verification::expire(&mut tx, now + 900).await.unwrap();
    verification::observe(
        &mut tx,
        "device",
        &Inventory {
            bitlocker_volumes: vec![on],
            ..Default::default()
        },
        13,
        now + 901,
    )
    .await
    .unwrap();
    verification::expire(&mut tx, now + 901).await.unwrap();
    tx.commit().await.unwrap();
    let states: Vec<(String, String)> =
        sqlx::query_as("SELECT id,verification_state FROM commands ORDER BY id")
            .fetch_all(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        states,
        vec![
            ("off".into(), "not_verified".into()),
            ("revoked".into(), "inconclusive".into()),
            ("unknown".into(), "inconclusive".into())
        ]
    );
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event='command_verification_closed'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(events, 3);
}

async fn role_session(app: &App, role: &str) -> String {
    sqlx::query("INSERT INTO users(id,tenant_id,username,password_hash,role,totp_secret) VALUES(?,'main',?,'unused',?,'unused')")
        .bind(role).bind(role).bind(role).execute(&app.pool).await.unwrap();
    let token = security::token();
    sqlx::query("INSERT INTO sessions VALUES(?,?,'csrf',?,?)")
        .bind(security::digest(token.as_bytes()))
        .bind(role)
        .bind(Utc::now().timestamp() + 3600)
        .bind(Utc::now().timestamp())
        .execute(&app.pool)
        .await
        .unwrap();
    token
}
async fn session_request(
    router: &Router,
    token: &str,
    path: &str,
    data: Option<serde_json::Value>,
) -> StatusCode {
    let mut request = Request::builder()
        .uri(path)
        .header("cookie", format!("punishell={token}"));
    let body = if let Some(data) = data {
        request = request
            .method("POST")
            .header("content-type", "application/json")
            .header("x-csrf-token", "csrf");
        Body::from(serde_json::to_vec(&data).unwrap())
    } else {
        Body::empty()
    };
    router
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn six_roles_separate_platform_operations_requests_and_audit() {
    use serde_json::json;
    let (_dir, app, router, provider) = fixture_with_provider().await;
    let original: String = sqlx::query_scalar("SELECT envelope FROM licenses LIMIT 1")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    let original: SignedEnvelope = serde_json::from_str(&original).unwrap();
    let mut claims: LicenseClaims =
        punishell_protocol::verify_license_signature(&original, &app.license_trust, Utc::now())
            .unwrap();
    claims.max_agents = 25;
    let signed = sign_license(&claims, LICENSE_KEY, &provider).unwrap();
    sqlx::query("UPDATE licenses SET envelope=?")
        .bind(serde_json::to_string(&signed).unwrap())
        .execute(&app.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO agents(id,tenant_id,public_key) VALUES('target','main','unused')")
        .execute(&app.pool)
        .await
        .unwrap();
    for role in [
        "security_observer",
        "requester",
        "approver",
        "technical_operator",
        "auditor",
        "platform_administrator",
    ] {
        let token = role_session(&app, role).await;
        for path in ["/api/v1/overview", "/api/v1/agents", "/api/v1/incidents"] {
            assert_eq!(
                session_request(&router, &token, path, None).await,
                StatusCode::OK,
                "{role} {path}"
            );
        }
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me")
                    .header("cookie", format!("punishell={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let me: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(me["role"], role); // API spelling must also match web permissions.
        assert_eq!(
            session_request(&router, &token, "/api/v1/users", None).await,
            if role == "platform_administrator" {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        assert_eq!(
            session_request(&router, &token, "/api/v1/audit", None).await,
            if ["auditor", "platform_administrator"].contains(&role) {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        assert_eq!(
            session_request(
                &router,
                &token,
                "/api/v1/activation-codes",
                Some(json!({"ttl_minutes":15}))
            )
            .await,
            if role == "technical_operator" {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        assert_eq!(
            session_request(
                &router,
                &token,
                "/api/v1/commands",
                Some(json!({"agent_id":"target","action":{"type":"collect_inventory"}}))
            )
            .await,
            if role == "requester" {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        if role != "approver" {
            assert_eq!(
                session_request(
                    &router,
                    &token,
                    "/api/v1/commands/absent/approve",
                    Some(json!({"totp":"000000"}))
                )
                .await,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                session_request(
                    &router,
                    &token,
                    "/api/v1/commands/absent/reject",
                    Some(json!({}))
                )
                .await,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            session_request(
                &router,
                &token,
                "/api/v1/agents/absent/revoke",
                Some(json!({}))
            )
            .await,
            if role == "technical_operator" {
                StatusCode::CONFLICT
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }
}

#[tokio::test]
async fn import_rejects_untrusted_altered_wrong_tenant_expired_and_replayed_licenses() {
    use serde_json::json;
    let (_dir, app, router, provider) = fixture_with_provider().await;
    let admin = role_session(&app, "platform_administrator").await;
    let observer = role_session(&app, "security_observer").await;
    let now = Utc::now();
    let claims = LicenseClaims {
        protocol_version: PROTOCOL_VERSION,
        license_id: "imported".into(),
        tenant_id: "main".into(),
        product: PRODUCT.into(),
        plan: "monthly".into(),
        features: BTreeSet::from([Feature::Inventory, Feature::WipeData]),
        max_agents: 25,
        issued_at: now,
        expires_at: now + Duration::days(30),
        offline_grace_hours: 72,
    };
    sqlx::query("UPDATE licenses SET issued_at=issued_at-1")
        .execute(&app.pool)
        .await
        .unwrap();
    let good = sign_license(&claims, LICENSE_KEY, &provider).unwrap();
    let path = "/api/v1/licenses/import";
    assert_eq!(
        session_request(&router, &observer, path, Some(json!(good))).await,
        StatusCode::FORBIDDEN
    );
    let bad = sign_license(&claims, LICENSE_KEY, &generate_signing_key()).unwrap();
    assert_eq!(
        session_request(&router, &admin, path, Some(json!(bad))).await,
        StatusCode::FORBIDDEN
    );
    for mutation in ["tenant", "product", "expired", "future"] {
        let mut bad = claims.clone();
        match mutation {
            "tenant" => bad.tenant_id = "other".into(),
            "product" => bad.product = "other".into(),
            "expired" => {
                bad.issued_at = now - Duration::days(2);
                bad.expires_at = now - Duration::days(1);
            }
            _ => {
                bad.issued_at = now + Duration::days(1);
                bad.expires_at = now + Duration::days(2);
            }
        }
        assert_eq!(
            session_request(
                &router,
                &admin,
                path,
                Some(json!(sign_license(&bad, LICENSE_KEY, &provider).unwrap()))
            )
            .await,
            StatusCode::FORBIDDEN,
            "{mutation}"
        );
    }
    let mut bad = good.clone();
    bad.payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"max_agents":99999})).unwrap());
    assert_eq!(
        session_request(&router, &admin, path, Some(json!(bad))).await,
        StatusCode::FORBIDDEN
    );
    let missing_csrf = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", format!("punishell={admin}"))
        .body(Body::from(serde_json::to_vec(&good).unwrap()))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(missing_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        session_request(&router, &admin, path, Some(json!(good))).await,
        StatusCode::OK
    );
    assert_eq!(
        session_request(&router, &admin, path, Some(json!(good))).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        session_request(&router, &admin, "/api/v1/licenses", Some(json!({}))).await,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        session_request(
            &router,
            &admin,
            "/api/v1/licenses/imported/revoke",
            Some(json!({}))
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let imported: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event='license_imported'")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(imported, 1);
    // Rotated/retired keys in historical records cannot hide the new active license.
    let untrusted = sign_license(&claims, LICENSE_KEY, &generate_signing_key()).unwrap();
    sqlx::query("UPDATE licenses SET envelope=? WHERE id!='imported'")
        .bind(serde_json::to_string(&untrusted).unwrap())
        .execute(&app.pool)
        .await
        .unwrap();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/licenses")
                .header("cookie", format!("punishell={admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let history: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(history[0]["state"], "active");
    assert_eq!(history[1]["state"], "invalid");
    assert!(!app.config.state_dir.join("license.key").exists());
}

#[tokio::test]
async fn formal_role_migration_preserves_foreign_keys_and_encrypted_secrets() {
    let (_dir, app, _router) = fixture().await;
    // Recreate the real v6 users schema, with live references from other tables.
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&app.pool)
        .await
        .unwrap();
    sqlx::raw_sql("DROP TABLE users;
        CREATE TABLE users(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id),username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('administrator','operator','approver','auditor')),
        totp_secret TEXT NOT NULL,last_totp INTEGER NOT NULL DEFAULT -1,disabled INTEGER NOT NULL DEFAULT 0);
        INSERT INTO users VALUES('admin','main','admin','hash','administrator','encrypted-secret',123,0),
          ('maker','main','maker','hash','operator','encrypted-maker',456,1),
          ('checker','main','checker','hash','approver','encrypted-checker',789,0),
          ('audit','main','audit','hash','auditor','encrypted-audit',999,0);
        INSERT INTO agents(id,tenant_id,public_key) VALUES('target','main','unused');
        INSERT INTO sessions VALUES('session','admin','csrf',9999999999,0);
        INSERT INTO password_resets VALUES('reset','maker',9999999999,NULL);
        INSERT INTO commands(id,tenant_id,agent_id,requester,approver,action,state,created_at,expires_at)
          VALUES('order','main','target','maker','checker','{}','approved',0,9999999999);
        INSERT INTO incidents(id,tenant_id,agent_id,kind,severity,state,first_seen,last_seen,evidence_at,detail,acknowledged_by)
          VALUES('incident','main','target','agent_offline','warning','acknowledged',0,0,0,'detail','admin');
        DELETE FROM schema_version WHERE version=7;")
        .execute(&app.pool).await.unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&app.pool)
        .await
        .unwrap();
    let config = app.config.clone();
    app.pool.close().await;
    let migrated = App::open(config.clone()).await.unwrap();
    let roles: Vec<(String, String)> = sqlx::query_as("SELECT id,role FROM users ORDER BY id")
        .fetch_all(&migrated.pool)
        .await
        .unwrap();
    assert_eq!(
        roles,
        vec![
            ("admin".into(), "platform_administrator".into()),
            ("audit".into(), "auditor".into()),
            ("checker".into(), "approver".into()),
            ("maker".into(), "requester".into())
        ]
    );
    let retained: (String, i64, bool) =
        sqlx::query_as("SELECT totp_secret,last_totp,disabled FROM users WHERE id='maker'")
            .fetch_one(&migrated.pool)
            .await
            .unwrap();
    assert_eq!(retained, ("encrypted-maker".into(), 456, true));
    for table in ["commands", "sessions", "password_resets", "incidents"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&migrated.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
    assert!(sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&migrated.pool)
        .await
        .unwrap()
        .is_empty());
    assert!(
        sqlx::query("UPDATE users SET role='operator' WHERE id='maker'")
            .execute(&migrated.pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("DELETE FROM users WHERE id='maker'")
        .execute(&migrated.pool)
        .await
        .is_err());
    migrated.pool.close().await;
    App::open(config).await.unwrap().pool.close().await;
}
