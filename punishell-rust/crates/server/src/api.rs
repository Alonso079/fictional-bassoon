use crate::{
    security,
    store::{
        self, audit, current_license, rate, App, Error, Result, Session, COMMAND_KEY, LICENSE_KEY,
        SERVER_KEY,
    },
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use ed25519_dalek::VerifyingKey;
use punishell_domain::{
    authorize_approval, authorize_request, validate_command, CommandPolicy, CommandState, Role,
};
use punishell_licensing::{require_agent_capacity, require_feature, subscription_expires_at};
use punishell_protocol::{
    decrypt_payload, encrypt_payload, sign_command, sign_license, sign_payload, valid_id,
    verify_payload, wire::*, Action, AgentWireEnvelope, CommandClaims, EncryptionDirection,
    Feature, LicenseClaims, Purpose, SignedEnvelope, TrustStore, TrustedKey, PRODUCT,
    PROTOCOL_VERSION,
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::{collections::BTreeSet, sync::Arc};

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::Domain(_) | Self::License(_) => StatusCode::FORBIDDEN,
            Self::Conflict => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Invalid(_) | Self::Protocol(_) | Self::Json(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() {
            eprintln!("Error interno: {self}");
        }
        (
            status,
            Json(json!({"error":status.canonical_reason().unwrap_or("error")})),
        )
            .into_response()
    }
}
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/javascript")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route("/health", get(liveness))
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/password", post(change_password))
        .route("/api/v1/password/reset", post(reset_password))
        .route("/api/v1/users", get(users).post(create_user))
        .route("/api/v1/users/{id}/disable", post(disable_user))
        .route("/api/v1/licenses", get(licenses).post(issue_license))
        .route("/api/v1/licenses/{id}/revoke", post(revoke_license))
        .route("/api/v1/activation-codes", post(activation_code))
        .route("/api/v1/enrollment/start", post(enrollment_start))
        .route("/api/v1/agent", post(device))
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/agents/{id}", get(agent_detail))
        .route("/api/v1/agents/{id}/telemetry", get(agent_telemetry))
        .route("/api/v1/agents/{id}/revoke", post(revoke_agent))
        .route("/api/v1/commands", get(commands).post(request_action))
        .route("/api/v1/commands/{id}/approve", post(approve_action))
        .route("/api/v1/commands/{id}/reject", post(reject_action))
        .route("/api/v1/commands/{id}/cancel", post(cancel_action))
        .route("/api/v1/audit", get(audit_log))
        .route("/api/v1/updates/{channel}", get(update_manifest))
        .route("/downloads/{filename}", get(download))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(axum::middleware::from_fn(headers))
        .with_state(app)
}
async fn headers(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let request_id = security::id();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let started = std::time::Instant::now();
    let mut response = next.run(req).await;
    for (key,value) in [("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
        ("strict-transport-security","max-age=31536000"),("x-content-type-options","nosniff"),("referrer-policy","no-referrer"),("cache-control","no-store")] {
        response.headers_mut().insert(axum::http::HeaderName::from_static(key),axum::http::HeaderValue::from_static(value));
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    eprintln!(
        "{}",
        json!({"event":"http_request","request_id":request_id,"method":method.as_str(),"path":path,"status":response.status().as_u16(),"duration_ms":started.elapsed().as_millis()})
    );
    response
}

async fn liveness() -> Json<Value> {
    Json(json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
}

async fn readiness(State(app): State<Arc<App>>) -> Result<Json<Value>> {
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&app.pool)
        .await?;
    if version != 4 {
        return Err(Error::Invalid("esquema no preparado"));
    }
    Ok(Json(
        json!({"status":"ready","version":env!("CARGO_PKG_VERSION"),"schema_version":version}),
    ))
}
async fn session(app: &App, headers: &HeaderMap, write: bool) -> Result<Session> {
    if headers
        .get(header::ORIGIN)
        .is_some_and(|v| v.to_str().ok() != Some(&app.config.public_url))
    {
        return Err(Error::Forbidden);
    }
    let token = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .map(str::trim)
                .find_map(|v| v.strip_prefix("punishell="))
        })
        .ok_or(Error::Unauthorized)?;
    if token.len() != 43 {
        return Err(Error::Unauthorized);
    }
    let hash = security::digest(token.as_bytes());
    let row=sqlx::query("SELECT u.id,u.tenant_id,u.role,s.csrf,s.mfa_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.disabled=0")
        .bind(&hash).bind(Utc::now().timestamp()).fetch_optional(&app.pool).await?.ok_or(Error::Unauthorized)?;
    let csrf: String = row.get("csrf");
    if write && headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(&csrf) {
        return Err(Error::Forbidden);
    }
    Ok(Session {
        user_id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        role: store::role(row.get("role"))?,
        csrf,
        mfa_at: chrono::DateTime::from_timestamp(row.get("mfa_at"), 0)
            .ok_or(Error::Unauthorized)?,
        token_hash: hash,
    })
}
fn admin(s: &Session) -> Result<()> {
    if s.role != Role::Administrator {
        return Err(Error::Forbidden);
    }
    Ok(())
}
async fn mfa(
    app: &App,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    code: &str,
    now: i64,
) -> Result<()> {
    let row = sqlx::query("SELECT totp_secret,last_totp FROM users WHERE id=? AND disabled=0")
        .bind(user)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::Unauthorized)?;
    let secret = security::decrypt(&app.encryption_key, user, row.get("totp_secret"))?;
    let counter = security::totp_counter(&secret, code, now, row.get("last_totp"))?;
    sqlx::query("UPDATE users SET last_totp=? WHERE id=?")
        .bind(counter)
        .bind(user)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
    totp: String,
}
async fn login(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response> {
    if headers
        .get(header::ORIGIN)
        .is_some_and(|v| v.to_str().ok() != Some(&app.config.public_url))
    {
        return Err(Error::Forbidden);
    }
    if !valid_id(&input.username) || input.password.len() > 128 {
        return Err(Error::Unauthorized);
    }
    let now = Utc::now().timestamp();
    rate(&app, "login-global", 120, 60, now).await?;
    rate(&app, &format!("login:{}", input.username), 10, 300, now).await?;
    let row = sqlx::query("SELECT id,password_hash FROM users WHERE username=? AND disabled=0")
        .bind(&input.username)
        .fetch_optional(&app.pool)
        .await?;
    let hash = row
        .as_ref()
        .map(|r| r.get::<String, _>("password_hash"))
        .unwrap_or_else(|| app.dummy_hash.clone());
    let _slot = app
        .password_slots
        .acquire()
        .await
        .map_err(|_| Error::Unauthorized)?;
    if !tokio::task::spawn_blocking(move || security::password_matches(&input.password, &hash))
        .await
        .map_err(|_| Error::Unauthorized)?
    {
        return Err(Error::Unauthorized);
    }
    let user: String = row.ok_or(Error::Unauthorized)?.get("id");
    let mut tx = app.pool.begin().await?;
    mfa(&app, &mut tx, &user, &input.totp, now).await?;
    let token = security::token();
    let csrf = security::token();
    sqlx::query("INSERT INTO sessions VALUES(?,?,?,?,?)")
        .bind(security::digest(token.as_bytes()))
        .bind(&user)
        .bind(&csrf)
        .bind(now + 8 * 3600)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        [(
            header::SET_COOKIE,
            format!("punishell={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800"),
        )],
        Json(json!({"csrf":csrf})),
    )
        .into_response())
}
async fn logout(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response> {
    let s = session(&app, &headers, true).await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash=?")
        .bind(s.token_hash)
        .execute(&app.pool)
        .await?;
    Ok((
        [(
            header::SET_COOKIE,
            "punishell=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        )],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn me(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    Ok(Json(
        json!({"id":s.user_id,"tenant_id":s.tenant_id,"role":format!("{:?}",s.role).to_lowercase(),"csrf":s.csrf}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUser {
    username: String,
    password: String,
    role: String,
}
pub async fn add_user(
    app: &App,
    tenant: &str,
    input_username: &str,
    password: &str,
    role: &str,
) -> Result<Value> {
    if !valid_id(input_username) {
        return Err(Error::Invalid("usuario"));
    }
    store::role(role)?;
    let user = security::id();
    let secret = security::new_totp_secret();
    let p = password.to_owned();
    let hash = tokio::task::spawn_blocking(move || security::password_hash(&p))
        .await
        .map_err(|_| Error::Invalid("contraseña"))??;
    let encrypted = security::encrypt(&app.encryption_key, &user, &secret)?;
    let mut tx = app.pool.begin().await?;
    sqlx::query("INSERT INTO users(id,tenant_id,username,password_hash,role,totp_secret) VALUES(?,?,?,?,?,?)").bind(&user).bind(tenant).bind(input_username).bind(hash).bind(role).bind(encrypted).execute(&mut *tx).await?;
    audit(
        &mut tx,
        tenant,
        "administrator",
        "user_created",
        &user,
        Utc::now().timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":user,"username":input_username,"totp_secret":security::secret_base32(&secret)}))
}
async fn create_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<NewUser>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    admin(&s)?;
    let _slot = app
        .password_slots
        .acquire()
        .await
        .map_err(|_| Error::Conflict)?;
    Ok(Json(
        add_user(
            &app,
            &s.tenant_id,
            &input.username,
            &input.password,
            &input.role,
        )
        .await?,
    ))
}
async fn users(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    admin(&s)?;
    let rows=sqlx::query("SELECT id,username,role,disabled FROM users WHERE tenant_id=? ORDER BY username LIMIT 1000").bind(s.tenant_id).fetch_all(&app.pool).await?;
    Ok(Json(json!(rows.iter().map(|r|json!({"id":r.get::<String,_>("id"),"username":r.get::<String,_>("username"),"role":r.get::<String,_>("role"),"disabled":r.get::<bool,_>("disabled")})).collect::<Vec<_>>())))
}
async fn disable_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    admin(&s)?;
    if id == s.user_id {
        return Err(Error::Forbidden);
    }
    let mut tx = app.pool.begin().await?;
    let n = sqlx::query("UPDATE users SET disabled=1 WHERE id=? AND tenant_id=?")
        .bind(&id)
        .bind(&s.tenant_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n != 1 {
        return Err(Error::Conflict);
    }
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        "user_disabled",
        &id,
        Utc::now().timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordChange {
    old_password: String,
    new_password: String,
    totp: String,
}
async fn change_password(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<PasswordChange>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    rate(
        &app,
        &format!("password:{}", s.user_id),
        5,
        300,
        Utc::now().timestamp(),
    )
    .await?;
    let old: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=?")
        .bind(&s.user_id)
        .fetch_one(&app.pool)
        .await?;
    let _slot = app
        .password_slots
        .acquire()
        .await
        .map_err(|_| Error::Conflict)?;
    let new = tokio::task::spawn_blocking(move || {
        if !security::password_matches(&input.old_password, &old) {
            return Err(Error::Unauthorized);
        }
        security::password_hash(&input.new_password)
    })
    .await
    .map_err(|_| Error::Unauthorized)??;
    let mut tx = app.pool.begin().await?;
    mfa(
        &app,
        &mut tx,
        &s.user_id,
        &input.totp,
        Utc::now().timestamp(),
    )
    .await?;
    sqlx::query("UPDATE users SET password_hash=? WHERE id=?")
        .bind(new)
        .bind(&s.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(&s.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordReset {
    token: String,
    new_password: String,
    totp: String,
}
async fn reset_password(
    State(app): State<Arc<App>>,
    Json(input): Json<PasswordReset>,
) -> Result<Json<Value>> {
    let now = Utc::now().timestamp();
    rate(&app, "reset-global", 20, 300, now).await?;
    if input.token.len() != 43 {
        return Err(Error::Unauthorized);
    }
    let row=sqlx::query("SELECT user_id FROM password_resets WHERE token_hash=? AND expires_at>? AND used_at IS NULL").bind(security::digest(input.token.as_bytes())).bind(now).fetch_optional(&app.pool).await?.ok_or(Error::Unauthorized)?;
    let user: String = row.get("user_id");
    let _slot = app
        .password_slots
        .acquire()
        .await
        .map_err(|_| Error::Conflict)?;
    let hash = tokio::task::spawn_blocking(move || security::password_hash(&input.new_password))
        .await
        .map_err(|_| Error::Unauthorized)??;
    let mut tx = app.pool.begin().await?;
    mfa(&app, &mut tx, &user, &input.totp, now).await?;
    let n=sqlx::query("UPDATE password_resets SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?").bind(now).bind(security::digest(input.token.as_bytes())).bind(now).execute(&mut *tx).await?.rows_affected();
    if n != 1 {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE users SET password_hash=? WHERE id=?")
        .bind(hash)
        .bind(&user)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueLicense {
    months: u32,
    plan: String,
    max_agents: u32,
    features: BTreeSet<Feature>,
    offline_grace_hours: u16,
}
async fn issue_license(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<IssueLicense>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    admin(&s)?;
    let now = Utc::now();
    if !valid_id(&input.plan)
        || input.max_agents == 0
        || input.max_agents > 10000
        || input.features.is_empty()
        || input.offline_grace_hours > 72
    {
        return Err(Error::Invalid("licencia"));
    }
    let claims = LicenseClaims {
        protocol_version: PROTOCOL_VERSION,
        license_id: security::id(),
        tenant_id: s.tenant_id.clone(),
        product: PRODUCT.into(),
        plan: input.plan,
        features: input.features,
        max_agents: input.max_agents,
        issued_at: now,
        expires_at: subscription_expires_at(now, input.months)?,
        offline_grace_hours: input.offline_grace_hours,
    };
    let envelope = sign_license(&claims, LICENSE_KEY, &app.license_key)?;
    let mut tx = app.pool.begin().await?;
    sqlx::query("INSERT INTO licenses(id,tenant_id,envelope,issued_at) VALUES(?,?,?,?)")
        .bind(&claims.license_id)
        .bind(&s.tenant_id)
        .bind(serde_json::to_string(&envelope)?)
        .bind(now.timestamp())
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        "license_issued",
        &claims.license_id,
        now.timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"claims":claims,"envelope":envelope})))
}
async fn licenses(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    let rows=sqlx::query("SELECT id,envelope,revoked FROM licenses WHERE tenant_id=? ORDER BY issued_at DESC,rowid DESC LIMIT 100").bind(s.tenant_id).fetch_all(&app.pool).await?;
    Ok(Json(json!(rows.iter().map(|r|json!({"id":r.get::<String,_>("id"),"envelope":serde_json::from_str::<Value>(r.get("envelope")).unwrap_or(Value::Null),"revoked":r.get::<bool,_>("revoked")})).collect::<Vec<_>>())))
}
async fn revoke_license(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    admin(&s)?;
    let mut tx = app.pool.begin().await?;
    let n = sqlx::query("UPDATE licenses SET revoked=1 WHERE id=? AND tenant_id=?")
        .bind(&id)
        .bind(&s.tenant_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n != 1 {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE commands SET state='cancelled' WHERE tenant_id=? AND state IN ('pending','approved')").bind(&s.tenant_id).execute(&mut *tx).await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        "license_revoked",
        &id,
        Utc::now().timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeOptions {
    ttl_minutes: u32,
}
async fn activation_code(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<CodeOptions>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    admin(&s)?;
    let now = Utc::now();
    if !(1..=1440).contains(&input.ttl_minutes) {
        return Err(Error::Invalid("TTL"));
    }
    let mut tx = app.pool.begin().await?;
    let (_, license, state, _) = current_license(&app, &mut tx, &s.tenant_id, now).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE tenant_id=? AND revoked=0")
            .bind(&s.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
    require_agent_capacity(&license, state, count as u32)?;
    let code = security::token();
    let expires = (now + Duration::minutes(input.ttl_minutes.into()))
        .timestamp()
        .min(license.expires_at.timestamp());
    sqlx::query("INSERT INTO activation_codes(code_hash,tenant_id,expires_at) VALUES(?,?,?)")
        .bind(security::digest(code.as_bytes()))
        .bind(&s.tenant_id)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        "activation_created",
        "code",
        now.timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"activation_code":code,"expires_at":expires})))
}
async fn enrollment_start(
    State(app): State<Arc<App>>,
    Json(input): Json<EnrollmentStart>,
) -> Result<Json<SignedEnvelope>> {
    let now = Utc::now();
    rate(&app, "enroll-global", 30, 60, now.timestamp()).await?;
    if !valid_id(&input.tenant_id) || input.activation_code.len() != 43 {
        return Err(Error::Unauthorized);
    }
    public_key(&input.public_key_b64)?;
    let row=sqlx::query("SELECT code_hash FROM activation_codes WHERE code_hash=? AND tenant_id=? AND expires_at>? AND used_at IS NULL").bind(security::digest(input.activation_code.as_bytes())).bind(&input.tenant_id).bind(now.timestamp()).fetch_optional(&app.pool).await?.ok_or(Error::Unauthorized)?;
    let challenge = EnrollmentChallenge {
        challenge_id: security::id(),
        agent_id: security::id(),
        tenant_id: input.tenant_id,
        nonce: security::token(),
        public_key_b64: input.public_key_b64,
        issued_at: now,
        expires_at: now + Duration::minutes(2),
    };
    sqlx::query("INSERT INTO challenges(id,tenant_id,agent_id,code_hash,public_key,nonce,expires_at) VALUES(?,?,?,?,?,?,?)").bind(&challenge.challenge_id).bind(&challenge.tenant_id).bind(&challenge.agent_id).bind(row.get::<String,_>("code_hash")).bind(&challenge.public_key_b64).bind(&challenge.nonce).bind(challenge.expires_at.timestamp()).execute(&app.pool).await?;
    Ok(Json(sign_payload(
        &challenge,
        Purpose::Server,
        SERVER_KEY,
        &app.server_key,
    )?))
}
fn public_key(value: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Unauthorized)?
        .try_into()
        .map_err(|_| Error::Unauthorized)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Unauthorized)
}
fn device_trust(id: &str, key: &str) -> Result<TrustStore> {
    let mut keys = TrustStore::new();
    keys.insert(
        id.into(),
        TrustedKey {
            key: public_key(key)?,
            not_before: chrono::DateTime::from_timestamp(0, 0).expect("epoch"),
            not_after: chrono::DateTime::from_timestamp(4_102_444_800, 0).expect("2100"),
            revoked: false,
        },
    );
    Ok(keys)
}

#[derive(Clone)]
struct TransportKey {
    id: String,
    key: [u8; 32],
}

fn stored_transport(
    app: &App,
    agent_id: &str,
    key_id: Option<String>,
    encrypted: Option<String>,
) -> Result<Option<TransportKey>> {
    match (key_id, encrypted) {
        (None, None) => Ok(None),
        (Some(id), Some(value)) if valid_id(&id) => {
            let key = security::decrypt(&app.encryption_key, agent_id, &value)?
                .try_into()
                .map_err(|_| Error::Unauthorized)?;
            Ok(Some(TransportKey { id, key }))
        }
        _ => Err(Error::Unauthorized),
    }
}

fn new_transport(app: &App, agent_id: &str) -> Result<(TransportKey, String)> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let transport = TransportKey {
        id: security::id(),
        key,
    };
    let stored = security::encrypt(&app.encryption_key, agent_id, &transport.key)?;
    Ok((transport, stored))
}

fn protected_response(
    signed: SignedEnvelope,
    agent_id: &str,
    transport: Option<&TransportKey>,
) -> Result<AgentWireEnvelope> {
    Ok(match transport {
        Some(transport) => AgentWireEnvelope::Encrypted(encrypt_payload(
            &signed,
            EncryptionDirection::ServerToAgent,
            agent_id,
            &transport.id,
            &transport.key,
        )?),
        None => AgentWireEnvelope::Signed(signed),
    })
}

fn receipt_context(agent_id: &str, request_id: &str) -> String {
    format!("receipt:{agent_id}:{request_id}")
}

fn seal_receipt(
    app: &App,
    agent_id: &str,
    request_id: &str,
    wire: &AgentWireEnvelope,
) -> Result<String> {
    let plaintext = serde_json::to_vec(wire)?;
    Ok(format!(
        "enc-v1:{}",
        security::encrypt(
            &app.encryption_key,
            &receipt_context(agent_id, request_id),
            &plaintext,
        )?
    ))
}

fn open_receipt(
    app: &App,
    agent_id: &str,
    request_id: &str,
    value: &str,
) -> Result<AgentWireEnvelope> {
    if let Some(encrypted) = value.strip_prefix("enc-v1:") {
        let plaintext = security::decrypt(
            &app.encryption_key,
            &receipt_context(agent_id, request_id),
            encrypted,
        )?;
        return Ok(serde_json::from_slice(&plaintext)?);
    }
    // Compatibilidad de lectura con recibos creados antes del esquema v2.
    Ok(serde_json::from_str(value)?)
}

async fn device(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(wire): Json<AgentWireEnvelope>,
) -> Result<Json<AgentWireEnvelope>> {
    let now = Utc::now();
    let mut tx = app.pool.begin().await?;
    let request_transport = match &wire {
        AgentWireEnvelope::Encrypted(encrypted) => {
            if !valid_id(&encrypted.agent_id) {
                return Err(Error::Unauthorized);
            }
            let row =
                sqlx::query("SELECT transport_key_id,transport_key,revoked FROM agents WHERE id=?")
                    .bind(&encrypted.agent_id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(Error::Unauthorized)?;
            if row.get::<bool, _>("revoked") {
                return Err(Error::Forbidden);
            }
            stored_transport(
                &app,
                &encrypted.agent_id,
                row.get("transport_key_id"),
                row.get("transport_key"),
            )?
            .ok_or(Error::Unauthorized)?
        }
        AgentWireEnvelope::Signed(_) => TransportKey {
            id: String::new(),
            key: [0; 32],
        },
    };
    let encrypted_request = matches!(&wire, AgentWireEnvelope::Encrypted(_));
    let supports_encryption = encrypted_request
        || headers
            .get("x-punishell-transport")
            .is_some_and(|value| value == "aes256gcm-v1");
    let envelope = match &wire {
        AgentWireEnvelope::Encrypted(encrypted) => decrypt_payload(
            encrypted,
            EncryptionDirection::AgentToServer,
            &encrypted.agent_id,
            &request_transport.id,
            &request_transport.key,
        )?,
        AgentWireEnvelope::Signed(signed) => signed.clone(),
    };
    if envelope.payload_b64.len() > 22000 || !valid_id(&envelope.key_id) {
        return Err(Error::Unauthorized);
    }
    // Solo pista de búsqueda, nunca identidad autenticada. Después se verifica Ed25519.
    let hint: DeviceRequest = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&envelope.payload_b64)
            .map_err(|_| Error::Unauthorized)?,
    )?;
    if hint.agent_id != envelope.key_id
        || !valid_id(&hint.request_id)
        || hint.sequence > i64::MAX as u64
    {
        return Err(Error::Unauthorized);
    }
    let hash = security::digest(serde_json::to_vec(&envelope)?.as_slice());
    let existing =
        sqlx::query("SELECT tenant_id,public_key,sequence,revoked,transport_key_id,transport_key FROM agents WHERE id=?")
            .bind(&hint.agent_id)
            .fetch_optional(&mut *tx)
            .await?;
    if existing
        .as_ref()
        .is_some_and(|r| r.get::<bool, _>("revoked"))
    {
        return Err(Error::Forbidden);
    }
    // Reintento byte por byte ya autenticado, incluso después de rotar la clave.
    if let Some(receipt) =
        sqlx::query("SELECT request_hash,response FROM receipts WHERE agent_id=? AND request_id=?")
            .bind(&hint.agent_id)
            .bind(&hint.request_id)
            .fetch_optional(&mut *tx)
            .await?
    {
        if receipt.get::<String, _>("request_hash") != hash {
            return Err(Error::Conflict);
        }
        let previous_wire = open_receipt(
            &app,
            &hint.agent_id,
            &hint.request_id,
            receipt.get("response"),
        )?;
        let signed = match &previous_wire {
            AgentWireEnvelope::Encrypted(encrypted) => {
                let transport = stored_transport(
                    &app,
                    &hint.agent_id,
                    existing
                        .as_ref()
                        .and_then(|row| row.get("transport_key_id")),
                    existing.as_ref().and_then(|row| row.get("transport_key")),
                )?
                .ok_or(Error::Unauthorized)?;
                decrypt_payload(
                    encrypted,
                    EncryptionDirection::ServerToAgent,
                    &hint.agent_id,
                    &transport.id,
                    &transport.key,
                )?
            }
            AgentWireEnvelope::Signed(signed) => signed.clone(),
        };
        let previous: ServerMessage = verify_payload(
            &signed,
            Purpose::Server,
            &store::trust(&[store::public_config(SERVER_KEY, &app.server_key)])?,
            now,
        )?;
        if previous.expires_at <= now {
            let row = existing.as_ref().ok_or(Error::Unauthorized)?;
            if let AgentOperation::RotateKey { public_key_b64, .. } = &hint.operation {
                if row.get::<String, _>("public_key") != *public_key_b64 {
                    return Err(Error::Conflict);
                }
            }
            let tenant: String = row.get("tenant_id");
            let (license, _, _, revoked) = current_license(&app, &mut tx, &tenant, now).await?;
            let refreshed = sign_payload(
                &ServerMessage {
                    request_id: hint.request_id.clone(),
                    agent_id: hint.agent_id.clone(),
                    issued_at: now,
                    expires_at: now + Duration::minutes(2),
                    revoked,
                    license,
                    command: None,
                    lease_token: None,
                    transport_key_id: previous.transport_key_id,
                    transport_key_b64: previous.transport_key_b64,
                },
                Purpose::Server,
                SERVER_KEY,
                &app.server_key,
            )?;
            let refreshed_wire = protected_response(
                refreshed,
                &hint.agent_id,
                encrypted_request.then_some(&request_transport),
            )?;
            sqlx::query(
                "UPDATE receipts SET response=?,created_at=? WHERE agent_id=? AND request_id=?",
            )
            .bind(seal_receipt(
                &app,
                &hint.agent_id,
                &hint.request_id,
                &refreshed_wire,
            )?)
            .bind(now.timestamp())
            .bind(&hint.agent_id)
            .bind(&hint.request_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(Json(refreshed_wire));
        }
        return Ok(Json(previous_wire));
    }
    if !encrypted_request
        && existing
            .as_ref()
            .is_some_and(|row| row.get::<Option<String>, _>("transport_key_id").is_some())
    {
        return Err(Error::Forbidden);
    }
    let (tenant, public, last) = if let Some(row) = existing.as_ref() {
        (
            row.get::<String, _>("tenant_id"),
            row.get::<String, _>("public_key"),
            row.get::<i64, _>("sequence"),
        )
    } else {
        let row=sqlx::query("SELECT tenant_id,public_key FROM challenges WHERE agent_id=? AND expires_at>? AND used_at IS NULL").bind(&hint.agent_id).bind(now.timestamp()).fetch_optional(&mut *tx).await?.ok_or(Error::Unauthorized)?;
        (row.get("tenant_id"), row.get("public_key"), -1)
    };
    let request: DeviceRequest = verify_payload(
        &envelope,
        Purpose::Device,
        &device_trust(&hint.agent_id, &public)?,
        now,
    )?;
    if request.issued_at > now + Duration::seconds(30)
        || now - request.issued_at > Duration::minutes(2)
        || request.sequence as i64 <= last
    {
        return Err(Error::Unauthorized);
    }
    let (license, claims, state, revoked) = current_license(&app, &mut tx, &tenant, now).await?;
    let mut command = None;
    let mut lease_token = None;
    let mut provision: Option<(TransportKey, String)> = None;
    if existing.is_some() && !encrypted_request && supports_encryption {
        let generated = new_transport(&app, &request.agent_id)?;
        sqlx::query("UPDATE agents SET transport_key_id=?,transport_key=? WHERE id=? AND transport_key_id IS NULL AND transport_key IS NULL")
            .bind(&generated.0.id)
            .bind(&generated.1)
            .bind(&request.agent_id)
            .execute(&mut *tx)
            .await?;
        provision = Some(generated);
    }
    match &request.operation {
        AgentOperation::Enroll {
            challenge_id,
            nonce,
        } => {
            if existing.is_some() {
                return Err(Error::Conflict);
            }
            let row=sqlx::query("SELECT code_hash FROM challenges WHERE id=? AND agent_id=? AND nonce=? AND expires_at>? AND used_at IS NULL").bind(challenge_id).bind(&request.agent_id).bind(nonce).bind(now.timestamp()).fetch_optional(&mut *tx).await?.ok_or(Error::Unauthorized)?;
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE tenant_id=? AND revoked=0")
                    .bind(&tenant)
                    .fetch_one(&mut *tx)
                    .await?;
            require_agent_capacity(&claims, state, count as u32)?;
            let n=sqlx::query("UPDATE activation_codes SET used_at=?,agent_id=? WHERE code_hash=? AND used_at IS NULL AND expires_at>?").bind(now.timestamp()).bind(&request.agent_id).bind(row.get::<String,_>("code_hash")).bind(now.timestamp()).execute(&mut *tx).await?.rows_affected();
            if n != 1 {
                return Err(Error::Conflict);
            }
            sqlx::query("UPDATE challenges SET used_at=? WHERE id=?")
                .bind(now.timestamp())
                .bind(challenge_id)
                .execute(&mut *tx)
                .await?;
            if supports_encryption {
                let generated = new_transport(&app, &request.agent_id)?;
                sqlx::query("INSERT INTO agents(id,tenant_id,public_key,sequence,transport_key_id,transport_key) VALUES(?,?,?,?,?,?)")
                    .bind(&request.agent_id)
                    .bind(&tenant)
                    .bind(&public)
                    .bind(request.sequence as i64)
                    .bind(&generated.0.id)
                    .bind(&generated.1)
                    .execute(&mut *tx)
                    .await?;
                provision = Some(generated);
            } else {
                sqlx::query("INSERT INTO agents(id,tenant_id,public_key,sequence) VALUES(?,?,?,?)")
                    .bind(&request.agent_id)
                    .bind(&tenant)
                    .bind(&public)
                    .bind(request.sequence as i64)
                    .execute(&mut *tx)
                    .await?;
            }
            audit(
                &mut tx,
                &tenant,
                &request.agent_id,
                "agent_enrolled",
                &request.agent_id,
                now.timestamp(),
            )
            .await?;
        }
        AgentOperation::Heartbeat { inventory, version } => {
            if existing.is_none() {
                return Err(Error::Unauthorized);
            }
            if version.len() > 64
                || serde_json::to_vec(inventory)?.len() > 10000
                || inventory.adapters.len() > 64
                || inventory.wifi.len() > 64
                || inventory.interactive_users.len() > 64
                || inventory.errors.len() > 64
            {
                return Err(Error::Invalid("inventario demasiado grande"));
            }
            let inventory_allowed = require_feature(&claims, state, Feature::Inventory).is_ok();
            let stored_inventory = if inventory_allowed {
                serde_json::to_string(inventory)?
            } else {
                "{}".into()
            };
            sqlx::query("UPDATE agents SET inventory=?,version=?,last_seen=? WHERE id=?")
                .bind(stored_inventory)
                .bind(version)
                .bind(now.timestamp())
                .bind(&request.agent_id)
                .execute(&mut *tx)
                .await?;
            if inventory_allowed {
                let bitlocker_protected = inventory
                    .bitlocker_volumes
                    .iter()
                    .filter(|volume| volume.protection_status == "on")
                    .count();
                let bitlocker_unprotected = inventory
                    .bitlocker_volumes
                    .iter()
                    .filter(|volume| volume.protection_status == "off")
                    .count();
                let bitlocker_unknown = inventory
                    .bitlocker_volumes
                    .len()
                    .saturating_sub(bitlocker_protected + bitlocker_unprotected);
                sqlx::query("INSERT INTO telemetry_samples(tenant_id,agent_id,captured_at,version,uptime_millis,disk_total_bytes,disk_free_bytes,ram_installed_bytes,ram_usable_bytes,adapter_count,wifi_count,interactive_user_count,error_count,bitlocker_protected_count,bitlocker_unprotected_count,bitlocker_unknown_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
                    .bind(&tenant)
                    .bind(&request.agent_id)
                    .bind(now.timestamp())
                    .bind(version)
                    .bind(i64::try_from(inventory.uptime_millis).unwrap_or(i64::MAX))
                    .bind(inventory.disk_total_bytes.and_then(|v| i64::try_from(v).ok()))
                    .bind(inventory.disk_free_bytes.and_then(|v| i64::try_from(v).ok()))
                    .bind(inventory.ram_installed_bytes.and_then(|v| i64::try_from(v).ok()))
                    .bind(inventory.ram_usable_bytes.and_then(|v| i64::try_from(v).ok()))
                    .bind(i64::try_from(inventory.adapters.len()).unwrap_or(i64::MAX))
                    .bind(i64::try_from(inventory.wifi.len()).unwrap_or(i64::MAX))
                    .bind(i64::try_from(inventory.interactive_users.len()).unwrap_or(i64::MAX))
                    .bind(i64::try_from(inventory.errors.len()).unwrap_or(i64::MAX))
                    .bind(i64::try_from(bitlocker_protected).unwrap_or(i64::MAX))
                    .bind(i64::try_from(bitlocker_unprotected).unwrap_or(i64::MAX))
                    .bind(i64::try_from(bitlocker_unknown).unwrap_or(i64::MAX))
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM telemetry_samples WHERE agent_id=? AND captured_at<?")
                    .bind(&request.agent_id)
                    .bind(now.timestamp() - 30 * 24 * 3600)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM telemetry_samples WHERE agent_id=? AND id NOT IN (SELECT id FROM telemetry_samples WHERE agent_id=? ORDER BY captured_at DESC,id DESC LIMIT 5000)")
                    .bind(&request.agent_id)
                    .bind(&request.agent_id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("UPDATE commands SET state='expired' WHERE agent_id=? AND expires_at<=? AND state IN ('pending','approved','claimed')").bind(&request.agent_id).bind(now.timestamp()).execute(&mut *tx).await?;
            if state == punishell_licensing::LicenseState::Active {
                if let Some(row)=sqlx::query("SELECT id,envelope,action FROM commands WHERE agent_id=? AND state='approved' AND expires_at>? ORDER BY created_at LIMIT 1").bind(&request.agent_id).bind(now.timestamp()).fetch_optional(&mut *tx).await? {
                    let action:Action=serde_json::from_str(row.get("action"))?;
                    if require_feature(&claims,state,action.required_feature()).is_ok(){
                        let token=security::token();let id:String=row.get("id");
                        sqlx::query("UPDATE commands SET state='claimed',lease_token=?,claimed_at=? WHERE id=? AND state='approved'").bind(&token).bind(now.timestamp()).bind(&id).execute(&mut *tx).await?;
                        command=Some(serde_json::from_str(row.get("envelope"))?);lease_token=Some(token);
                        audit(&mut tx,&tenant,&request.agent_id,"command_claimed",&id,now.timestamp()).await?;
                    }
                }
            }
        }
        AgentOperation::Complete {
            command_id,
            lease_token,
            success,
            output,
        } => {
            if existing.is_none() || output.len() > 8000 {
                return Err(Error::Invalid("resultado"));
            }
            let row = sqlx::query(
                "SELECT state,output FROM commands WHERE id=? AND agent_id=? AND lease_token=?",
            )
            .bind(command_id)
            .bind(&request.agent_id)
            .bind(lease_token)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::Forbidden)?;
            let current: String = row.get("state");
            let target = if *success { "succeeded" } else { "failed" };
            if current == "claimed" || current == "expired" {
                sqlx::query("UPDATE commands SET state=?,output=?,completed_at=? WHERE id=?")
                    .bind(target)
                    .bind(output)
                    .bind(now.timestamp())
                    .bind(command_id)
                    .execute(&mut *tx)
                    .await?;
                audit(
                    &mut tx,
                    &tenant,
                    &request.agent_id,
                    "command_finished",
                    command_id,
                    now.timestamp(),
                )
                .await?;
            } else if current != target
                || row.get::<Option<String>, _>("output").as_deref() != Some(output)
            {
                return Err(Error::Conflict);
            }
        }
        AgentOperation::RotateKey {
            command_id,
            lease_token,
            public_key_b64,
            proof,
        } => {
            if existing.is_none() {
                return Err(Error::Unauthorized);
            }
            require_feature(&claims, state, Feature::RotateIdentity)?;
            let row=sqlx::query("SELECT action FROM commands WHERE id=? AND agent_id=? AND lease_token=? AND state='claimed' AND expires_at>?").bind(command_id).bind(&request.agent_id).bind(lease_token).bind(now.timestamp()).fetch_optional(&mut *tx).await?.ok_or(Error::Forbidden)?;
            if !matches!(
                serde_json::from_str::<Action>(row.get("action"))?,
                Action::RotateAgentKey
            ) {
                return Err(Error::Forbidden);
            }
            let rotation: RotationProof = verify_payload(
                proof,
                Purpose::Device,
                &device_trust(&request.agent_id, public_key_b64)?,
                now,
            )?;
            if rotation.agent_id != request.agent_id
                || rotation.request_id != request.request_id
                || rotation.public_key_b64 != *public_key_b64
            {
                return Err(Error::Forbidden);
            }
            sqlx::query("UPDATE agents SET public_key=? WHERE id=?")
                .bind(public_key_b64)
                .bind(&request.agent_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE commands SET state='succeeded',output='identity rotated',completed_at=? WHERE id=?").bind(now.timestamp()).bind(command_id).execute(&mut *tx).await?;
            audit(
                &mut tx,
                &tenant,
                &request.agent_id,
                "identity_rotated",
                command_id,
                now.timestamp(),
            )
            .await?;
        }
    }
    sqlx::query("UPDATE agents SET sequence=? WHERE id=?")
        .bind(request.sequence as i64)
        .bind(&request.agent_id)
        .execute(&mut *tx)
        .await?;
    let response = sign_payload(
        &ServerMessage {
            request_id: request.request_id.clone(),
            agent_id: request.agent_id.clone(),
            issued_at: now,
            expires_at: now + Duration::minutes(2),
            revoked,
            license,
            command,
            lease_token,
            transport_key_id: provision.as_ref().map(|value| value.0.id.clone()),
            transport_key_b64: provision
                .as_ref()
                .map(|value| URL_SAFE_NO_PAD.encode(value.0.key)),
        },
        Purpose::Server,
        SERVER_KEY,
        &app.server_key,
    )?;
    let response_wire = protected_response(
        response,
        &request.agent_id,
        encrypted_request.then_some(&request_transport),
    )?;
    sqlx::query("INSERT INTO receipts VALUES(?,?,?,?,?)")
        .bind(&request.agent_id)
        .bind(&request.request_id)
        .bind(hash)
        .bind(seal_receipt(
            &app,
            &request.agent_id,
            &request.request_id,
            &response_wire,
        )?)
        .bind(now.timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(response_wire))
}

#[derive(Deserialize)]
struct Page {
    offset: Option<u32>,
}

fn agent_status(last_seen: Option<i64>, revoked: bool, now: i64) -> &'static str {
    if revoked {
        "revoked"
    } else if last_seen.is_some_and(|seen| seen >= now - 120) {
        "online"
    } else if last_seen.is_some_and(|seen| seen >= now - 900) {
        "stale"
    } else {
        "offline"
    }
}

async fn overview(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    let now = Utc::now().timestamp();
    let agents = sqlx::query("SELECT COUNT(*) total,COALESCE(SUM(CASE WHEN revoked=0 AND last_seen>=? THEN 1 ELSE 0 END),0) online,COALESCE(SUM(CASE WHEN revoked=0 AND last_seen<? AND last_seen>=? THEN 1 ELSE 0 END),0) stale,COALESCE(SUM(CASE WHEN revoked=0 AND (last_seen IS NULL OR last_seen<?) THEN 1 ELSE 0 END),0) offline,COALESCE(SUM(CASE WHEN revoked=1 THEN 1 ELSE 0 END),0) revoked FROM agents WHERE tenant_id=?")
        .bind(now - 120)
        .bind(now - 120)
        .bind(now - 900)
        .bind(now - 900)
        .bind(&s.tenant_id)
        .fetch_one(&app.pool)
        .await?;
    let commands = sqlx::query("SELECT COALESCE(SUM(CASE WHEN state='pending' THEN 1 ELSE 0 END),0) pending,COALESCE(SUM(CASE WHEN state='approved' THEN 1 ELSE 0 END),0) approved,COALESCE(SUM(CASE WHEN state='claimed' THEN 1 ELSE 0 END),0) running,COALESCE(SUM(CASE WHEN state='failed' AND completed_at>=? THEN 1 ELSE 0 END),0) failed_24h FROM commands WHERE tenant_id=?")
        .bind(now - 24 * 3600)
        .bind(&s.tenant_id)
        .fetch_one(&app.pool)
        .await?;
    let samples: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM telemetry_samples WHERE tenant_id=? AND captured_at>=?",
    )
    .bind(&s.tenant_id)
    .bind(now - 24 * 3600)
    .fetch_one(&app.pool)
    .await?;
    let inventory_rows =
        sqlx::query("SELECT inventory FROM agents WHERE tenant_id=? AND revoked=0")
            .bind(&s.tenant_id)
            .fetch_all(&app.pool)
            .await?;
    let mut bitlocker_protected = 0usize;
    let mut bitlocker_unprotected = 0usize;
    let mut bitlocker_unknown = 0usize;
    for row in inventory_rows {
        if let Ok(inventory) = serde_json::from_str::<Inventory>(row.get("inventory")) {
            bitlocker_protected += inventory
                .bitlocker_volumes
                .iter()
                .filter(|volume| volume.protection_status == "on")
                .count();
            bitlocker_unprotected += inventory
                .bitlocker_volumes
                .iter()
                .filter(|volume| volume.protection_status == "off")
                .count();
            bitlocker_unknown += inventory
                .bitlocker_volumes
                .iter()
                .filter(|volume| volume.protection_status == "unknown")
                .count();
        }
    }
    let license = if let Some(row) = sqlx::query(
        "SELECT envelope,revoked FROM licenses WHERE tenant_id=? ORDER BY issued_at DESC,rowid DESC LIMIT 1",
    )
    .bind(&s.tenant_id)
    .fetch_optional(&app.pool)
    .await?
    {
        let envelope: SignedEnvelope = serde_json::from_str(row.get("envelope"))?;
        let claims: LicenseClaims = verify_payload(
            &envelope,
            Purpose::License,
            &app.license_trust,
            Utc::now(),
        )?;
        json!({"plan":claims.plan,"expires_at":claims.expires_at,"max_agents":claims.max_agents,"revoked":row.get::<bool,_>("revoked")})
    } else {
        Value::Null
    };
    Ok(Json(json!({
        "agents": {"total":agents.get::<i64,_>("total"),"online":agents.get::<i64,_>("online"),"stale":agents.get::<i64,_>("stale"),"offline":agents.get::<i64,_>("offline"),"revoked":agents.get::<i64,_>("revoked")},
        "commands": {"pending":commands.get::<i64,_>("pending"),"approved":commands.get::<i64,_>("approved"),"running":commands.get::<i64,_>("running"),"failed_24h":commands.get::<i64,_>("failed_24h")},
        "telemetry_samples_24h": samples,
        "bitlocker": {"protected":bitlocker_protected,"unprotected":bitlocker_unprotected,"unknown":bitlocker_unknown},
        "license": license,
        "generated_at": now
    })))
}

async fn agents(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    let now = Utc::now().timestamp();
    let rows=sqlx::query("SELECT id,inventory,last_seen,version,revoked FROM agents WHERE tenant_id=? ORDER BY id LIMIT 100 OFFSET ?").bind(s.tenant_id).bind(page.offset.unwrap_or(0)).fetch_all(&app.pool).await?;
    Ok(Json(json!(rows.iter().map(|r|{
        let last_seen=r.get::<Option<i64>,_>("last_seen");
        let revoked=r.get::<bool,_>("revoked");
        json!({"id":r.get::<String,_>("id"),"inventory":serde_json::from_str::<Value>(r.get("inventory")).unwrap_or(Value::Null),"last_seen":last_seen,"version":r.get::<String,_>("version"),"revoked":revoked,"status":agent_status(last_seen,revoked,now)})
    }).collect::<Vec<_>>())))
}

async fn agent_detail(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    let row=sqlx::query("SELECT id,inventory,last_seen,version,revoked,sequence FROM agents WHERE id=? AND tenant_id=?").bind(&id).bind(&s.tenant_id).fetch_optional(&app.pool).await?.ok_or(Error::Conflict)?;
    let last_seen = row.get::<Option<i64>, _>("last_seen");
    let revoked = row.get::<bool, _>("revoked");
    let commands=sqlx::query("SELECT id,action,state,created_at,expires_at,output,completed_at FROM commands WHERE agent_id=? AND tenant_id=? ORDER BY created_at DESC,rowid DESC LIMIT 20").bind(&id).bind(&s.tenant_id).fetch_all(&app.pool).await?;
    Ok(Json(json!({
        "id":id,
        "status":agent_status(last_seen,revoked,Utc::now().timestamp()),
        "last_seen":last_seen,
        "version":row.get::<String,_>("version"),
        "revoked":revoked,
        "sequence":row.get::<i64,_>("sequence"),
        "inventory":serde_json::from_str::<Value>(row.get("inventory")).unwrap_or(Value::Null),
        "commands":commands.iter().map(|r|json!({"id":r.get::<String,_>("id"),"action":serde_json::from_str::<Value>(r.get("action")).unwrap_or(Value::Null),"state":r.get::<String,_>("state"),"created_at":r.get::<i64,_>("created_at"),"expires_at":r.get::<i64,_>("expires_at"),"output":r.get::<Option<String>,_>("output"),"completed_at":r.get::<Option<i64>,_>("completed_at")})).collect::<Vec<_>>()
    })))
}

#[derive(Deserialize)]
struct TelemetryPage {
    hours: Option<u16>,
    limit: Option<u16>,
}

async fn agent_telemetry(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(page): Query<TelemetryPage>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    if !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE id=? AND tenant_id=?)",
    )
    .bind(&id)
    .bind(&s.tenant_id)
    .fetch_one(&app.pool)
    .await?
    {
        return Err(Error::Conflict);
    }
    let hours = i64::from(page.hours.unwrap_or(24).clamp(1, 720));
    let limit = i64::from(page.limit.unwrap_or(288).clamp(1, 2000));
    let rows=sqlx::query("SELECT * FROM (SELECT captured_at,version,uptime_millis,disk_total_bytes,disk_free_bytes,ram_installed_bytes,ram_usable_bytes,adapter_count,wifi_count,interactive_user_count,error_count,bitlocker_protected_count,bitlocker_unprotected_count,bitlocker_unknown_count FROM telemetry_samples WHERE agent_id=? AND tenant_id=? AND captured_at>=? ORDER BY captured_at DESC,id DESC LIMIT ?) ORDER BY captured_at ASC")
        .bind(&id).bind(&s.tenant_id).bind(Utc::now().timestamp()-hours*3600).bind(limit).fetch_all(&app.pool).await?;
    Ok(Json(json!(rows.iter().map(|r|json!({
        "captured_at":r.get::<i64,_>("captured_at"),"version":r.get::<String,_>("version"),"uptime_millis":r.get::<i64,_>("uptime_millis"),
        "disk_total_bytes":r.get::<Option<i64>,_>("disk_total_bytes"),"disk_free_bytes":r.get::<Option<i64>,_>("disk_free_bytes"),
        "ram_installed_bytes":r.get::<Option<i64>,_>("ram_installed_bytes"),"ram_usable_bytes":r.get::<Option<i64>,_>("ram_usable_bytes"),
        "adapter_count":r.get::<i64,_>("adapter_count"),"wifi_count":r.get::<i64,_>("wifi_count"),"interactive_user_count":r.get::<i64,_>("interactive_user_count"),"error_count":r.get::<i64,_>("error_count"),
        "bitlocker_protected_count":r.get::<i64,_>("bitlocker_protected_count"),"bitlocker_unprotected_count":r.get::<i64,_>("bitlocker_unprotected_count"),"bitlocker_unknown_count":r.get::<i64,_>("bitlocker_unknown_count")
    })).collect::<Vec<_>>())))
}
async fn revoke_agent(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    admin(&s)?;
    let mut tx = app.pool.begin().await?;
    if sqlx::query("UPDATE agents SET revoked=1 WHERE id=? AND tenant_id=?")
        .bind(&id)
        .bind(&s.tenant_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE commands SET state='cancelled' WHERE agent_id=? AND state IN ('pending','approved')").bind(&id).execute(&mut *tx).await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        "agent_revoked",
        &id,
        Utc::now().timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
async fn request_action(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<RequestAction>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    authorize_request(&s.actor(), &s.tenant_id)?;
    let now = Utc::now();
    let mut tx = app.pool.begin().await?;
    if !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE id=? AND tenant_id=? AND revoked=0)",
    )
    .bind(&input.agent_id)
    .bind(&s.tenant_id)
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(Error::Forbidden);
    }
    let (_, license, state, _) = current_license(&app, &mut tx, &s.tenant_id, now).await?;
    require_feature(&license, state, input.action.required_feature())?;
    let id = security::id();
    let probe = CommandClaims {
        protocol_version: PROTOCOL_VERSION,
        command_id: id.clone(),
        tenant_id: s.tenant_id.clone(),
        agent_id: input.agent_id.clone(),
        issued_at: now,
        expires_at: now + Duration::minutes(5),
        nonce: security::digest(security::token().as_bytes())[..32].into(),
        approval_id: Some("pending-validation".into()),
        action: input.action.clone(),
    };
    validate_command(
        &probe,
        &CommandPolicy {
            tenant_id: &s.tenant_id,
            agent_id: &input.agent_id,
            now,
            enabled_features: &license.features,
            managed_services: &app.config.managed_services,
            update_channels: &app.config.update_channels,
        },
    )?;
    sqlx::query("INSERT INTO commands(id,tenant_id,agent_id,requester,action,state,created_at,expires_at) VALUES(?,?,?,?,?,'pending',?,?)").bind(&id).bind(&s.tenant_id).bind(&input.agent_id).bind(&s.user_id).bind(serde_json::to_string(&input.action)?).bind(now.timestamp()).bind((now+Duration::minutes(15)).timestamp()).execute(&mut *tx).await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        "command_requested",
        &id,
        now.timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id,"state":"pending"})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    totp: String,
}
async fn approve_action(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Approval>,
) -> Result<Json<Value>> {
    let mut s = session(&app, &headers, true).await?;
    let now = Utc::now();
    rate(&app, &format!("mfa:{}", s.user_id), 5, 300, now.timestamp()).await?;
    let mut tx = app.pool.begin().await?;
    let row=sqlx::query("SELECT agent_id,requester,action FROM commands WHERE id=? AND tenant_id=? AND state='pending' AND expires_at>?").bind(&id).bind(&s.tenant_id).bind(now.timestamp()).fetch_optional(&mut *tx).await?.ok_or(Error::Conflict)?;
    mfa(&app, &mut tx, &s.user_id, &input.totp, now.timestamp()).await?;
    s.mfa_at = now;
    authorize_approval(
        &s.actor(),
        &s.tenant_id,
        row.get("requester"),
        CommandState::Pending,
        now,
    )?;
    let (_, license, state, _) = current_license(&app, &mut tx, &s.tenant_id, now).await?;
    let action: Action = serde_json::from_str(row.get("action"))?;
    require_feature(&license, state, action.required_feature())?;
    let agent: String = row.get("agent_id");
    if !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE id=? AND revoked=0)",
    )
    .bind(&agent)
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(Error::Forbidden);
    }
    let approval = security::id();
    let claims = CommandClaims {
        protocol_version: PROTOCOL_VERSION,
        command_id: id.clone(),
        tenant_id: s.tenant_id.clone(),
        agent_id: agent,
        issued_at: now,
        expires_at: now + Duration::minutes(5),
        nonce: security::digest(security::token().as_bytes())[..32].into(),
        approval_id: Some(approval.clone()),
        action,
    };
    let envelope = sign_command(&claims, COMMAND_KEY, &app.command_key)?;
    sqlx::query("UPDATE commands SET state='approved',approver=?,approval_id=?,envelope=?,expires_at=? WHERE id=? AND state='pending'").bind(&s.user_id).bind(approval).bind(serde_json::to_string(&envelope)?).bind(claims.expires_at.timestamp()).bind(&id).execute(&mut *tx).await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        "command_approved",
        &id,
        now.timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
async fn reject_action(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    if s.role != Role::Approver {
        return Err(Error::Forbidden);
    }
    end_action(&app, &s, &id, "rejected", false).await
}
async fn cancel_action(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, true).await?;
    end_action(&app, &s, &id, "cancelled", true).await
}
async fn end_action(
    app: &App,
    s: &Session,
    id: &str,
    target: &str,
    own: bool,
) -> Result<Json<Value>> {
    let mut tx = app.pool.begin().await?;
    let n=sqlx::query("UPDATE commands SET state=? WHERE id=? AND tenant_id=? AND state IN ('pending','approved') AND (?=0 OR requester=?)").bind(target).bind(id).bind(&s.tenant_id).bind(own).bind(&s.user_id).execute(&mut *tx).await?.rows_affected();
    if n != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        &s.tenant_id,
        &s.user_id,
        target,
        id,
        Utc::now().timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
async fn commands(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    let rows=sqlx::query("SELECT id,agent_id,requester,action,state,created_at,expires_at,output,completed_at FROM commands WHERE tenant_id=? ORDER BY created_at DESC,rowid DESC LIMIT 100 OFFSET ?").bind(s.tenant_id).bind(page.offset.unwrap_or(0)).fetch_all(&app.pool).await?;
    Ok(Json(json!(rows.iter().map(|r|json!({"id":r.get::<String,_>("id"),"agent_id":r.get::<String,_>("agent_id"),"requester":r.get::<String,_>("requester"),"action":serde_json::from_str::<Value>(r.get("action")).unwrap_or(Value::Null),"state":r.get::<String,_>("state"),"created_at":r.get::<i64,_>("created_at"),"expires_at":r.get::<i64,_>("expires_at"),"output":r.get::<Option<String>,_>("output"),"completed_at":r.get::<Option<i64>,_>("completed_at")})).collect::<Vec<_>>())))
}
async fn audit_log(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    let s = session(&app, &headers, false).await?;
    if !matches!(s.role, Role::Administrator | Role::Auditor) {
        return Err(Error::Forbidden);
    }
    let rows=sqlx::query("SELECT id,actor,event,object_id,at,previous_hash,hash FROM audit WHERE tenant_id=? ORDER BY id DESC LIMIT 100 OFFSET ?").bind(s.tenant_id).bind(page.offset.unwrap_or(0)).fetch_all(&app.pool).await?;
    Ok(Json(json!(rows.iter().map(|r|json!({"id":r.get::<i64,_>("id"),"actor":r.get::<String,_>("actor"),"event":r.get::<String,_>("event"),"object":r.get::<String,_>("object_id"),"at":r.get::<i64,_>("at"),"previous_hash":r.get::<String,_>("previous_hash"),"hash":r.get::<String,_>("hash")})).collect::<Vec<_>>())))
}
async fn update_manifest(
    State(app): State<Arc<App>>,
    Path(channel): Path<String>,
) -> Result<Json<SignedEnvelope>> {
    let raw: String = sqlx::query_scalar("SELECT envelope FROM updates WHERE channel=?")
        .bind(channel)
        .fetch_optional(&app.pool)
        .await?
        .ok_or(Error::Conflict)?;
    Ok(Json(serde_json::from_str(&raw)?))
}
async fn download(State(app): State<Arc<App>>, Path(filename): Path<String>) -> Result<Response> {
    let path: String = sqlx::query_scalar("SELECT file_path FROM updates WHERE filename=?")
        .bind(filename)
        .fetch_optional(&app.pool)
        .await?
        .ok_or(Error::Conflict)?;
    let size = tokio::fs::metadata(&path).await?.len();
    if size > 64 * 1024 * 1024 {
        return Err(Error::Invalid("artefacto demasiado grande"));
    }
    let bytes = tokio::fs::read(path).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}
