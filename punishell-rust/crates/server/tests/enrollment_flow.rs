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
async fn fixture() -> (tempfile::TempDir, std::sync::Arc<App>, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    for name in ["command", "license", "server", "update", "encryption"] {
        write_private(
            &state.join(format!("{name}.key")),
            &generate_signing_key().to_bytes(),
        )
        .unwrap();
    }
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
    let signed = sign_license(&license, LICENSE_KEY, &app.license_key).unwrap();
    sqlx::query("INSERT INTO licenses(id,tenant_id,envelope,issued_at) VALUES(?,'main',?,?)")
        .bind(&license.license_id)
        .bind(serde_json::to_string(&signed).unwrap())
        .bind(now.timestamp())
        .execute(&app.pool)
        .await
        .unwrap();
    let router = api::router(app.clone());
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
    assert_eq!(ready["schema_version"], 4);
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
}

#[tokio::test]
async fn administrator_login_six_month_license_and_activation_code() {
    let (_dir, app, router) = fixture().await;
    let created = api::add_user(
        &app,
        "main",
        "owner",
        "una-contrasena-segura-para-prueba",
        "administrator",
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
    let license_request=Request::builder().method("POST").uri("/api/v1/licenses").header("content-type","application/json").header("cookie",&cookie).header("x-csrf-token",csrf)
        .body(Body::from(serde_json::to_vec(&serde_json::json!({"months":6,"plan":"business","max_agents":2,"features":["inventory"],"offline_grace_hours":24})).unwrap())).unwrap();
    let response = router.clone().oneshot(license_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issued: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let start: chrono::DateTime<Utc> = issued["claims"]["issued_at"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let expiry: chrono::DateTime<Utc> = issued["claims"]["expires_at"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        expiry,
        punishell_licensing::subscription_expires_at(start, 6).unwrap()
    );
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
