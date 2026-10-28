use crate::security;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use punishell_domain::{Actor, Role};
use punishell_licensing::{verify_license, LicenseContext, LicenseState};
use punishell_protocol::{
    wire::PublicKeyConfig, LicenseClaims, SignedEnvelope, TrustStore, TrustedKey,
};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    Row, Sqlite, SqlitePool, Transaction,
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("no autenticado")]
    Unauthorized,
    #[error("no autorizado")]
    Forbidden,
    #[error("conflicto o recurso inexistente")]
    Conflict,
    #[error("demasiados intentos")]
    RateLimited,
    #[error("base de datos")]
    Database(#[from] sqlx::Error),
    #[error("JSON")]
    Json(#[from] serde_json::Error),
    #[error("archivo")]
    Io(#[from] std::io::Error),
    #[error("firma")]
    Protocol(#[from] punishell_protocol::ProtocolError),
    #[error("licencia")]
    License(#[from] punishell_licensing::LicenseError),
    #[error("política")]
    Domain(#[from] punishell_domain::DomainError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub bind: String,
    pub public_url: String,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub managed_services: BTreeSet<String>,
    pub update_channels: BTreeSet<String>,
}
pub struct App {
    pub pool: SqlitePool,
    pub config: Config,
    pub command_key: SigningKey,
    pub license_key: SigningKey,
    pub server_key: SigningKey,
    pub update_key: SigningKey,
    pub encryption_key: [u8; 32],
    pub license_trust: TrustStore,
    pub password_slots: tokio::sync::Semaphore,
    pub dummy_hash: String,
}
pub const COMMAND_KEY: &str = "command-v1";
pub const LICENSE_KEY: &str = "license-v1";
pub const SERVER_KEY: &str = "server-v1";
pub const UPDATE_KEY: &str = "update-v1";

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
fn read_secret(path: &Path) -> Result<[u8; 32]> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid("clave debe tener permisos 0600"));
        }
    }
    std::fs::read(path)?
        .try_into()
        .map_err(|_| Error::Invalid("clave debe medir 32 bytes"))
}
pub fn public_config(key_id: &str, key: &SigningKey) -> PublicKeyConfig {
    PublicKeyConfig {
        key_id: key_id.into(),
        public_key_b64: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        not_before: DateTime::from_timestamp(0, 0).expect("epoch"),
        not_after: DateTime::from_timestamp(4_102_444_800, 0).expect("2100"),
    }
}
pub fn trust(configs: &[PublicKeyConfig]) -> Result<TrustStore> {
    let mut store = TrustStore::new();
    for c in configs {
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&c.public_key_b64)
            .map_err(|_| Error::Invalid("clave pública"))?
            .try_into()
            .map_err(|_| Error::Invalid("clave pública"))?;
        if !punishell_protocol::valid_id(&c.key_id)
            || c.not_before >= c.not_after
            || store.contains_key(&c.key_id)
        {
            return Err(Error::Invalid("trust store"));
        }
        store.insert(
            c.key_id.clone(),
            TrustedKey {
                key: VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| Error::Invalid("clave pública"))?,
                not_before: c.not_before,
                not_after: c.not_after,
                revoked: false,
            },
        );
    }
    Ok(store)
}

impl App {
    pub async fn open(config: Config) -> Result<Arc<Self>> {
        if !config.public_url.starts_with("https://") || config.public_url.ends_with('/') {
            return Err(Error::Invalid("public_url HTTPS sin slash final"));
        }
        let command_key =
            SigningKey::from_bytes(&read_secret(&config.state_dir.join("command.key"))?);
        let license_key =
            SigningKey::from_bytes(&read_secret(&config.state_dir.join("license.key"))?);
        let server_key =
            SigningKey::from_bytes(&read_secret(&config.state_dir.join("server.key"))?);
        let update_key =
            SigningKey::from_bytes(&read_secret(&config.state_dir.join("update.key"))?);
        let encryption_key = read_secret(&config.state_dir.join("encryption.key"))?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(config.state_dir.join("punishell.db"))
                    .create_if_missing(true)
                    .foreign_keys(true)
                    .journal_mode(SqliteJournalMode::Wal)
                    .busy_timeout(Duration::from_secs(5)),
            )
            .await?;
        // Versionado explícito; no se ejecuta un esquema destructivo sobre una DB existente.
        sqlx::query("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await?;
        if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schema_version")
            .fetch_one(&pool)
            .await?
            == 0
        {
            let mut tx = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0001_system.sql"))
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO schema_version VALUES (1)")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(&pool)
            .await?;
        if version == 1 {
            let mut tx = pool.begin().await?;
            sqlx::raw_sql(include_str!(
                "../migrations/0002_agent_transport_encryption.sql"
            ))
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO schema_version VALUES (2)")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(&pool)
            .await?;
        if version == 2 {
            let mut tx = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0003_telemetry.sql"))
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO schema_version VALUES (3)")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(&pool)
            .await?;
        if version == 3 {
            let mut tx = pool.begin().await?;
            sqlx::raw_sql(include_str!("../migrations/0004_bitlocker_telemetry.sql"))
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO schema_version VALUES (4)")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(&pool)
            .await?;
        if version != 4 {
            return Err(Error::Invalid("versión DB incompatible"));
        }
        let license_trust = trust(&[public_config(LICENSE_KEY, &license_key)])?;
        let dummy_hash = security::password_hash(&security::token())?;
        Ok(Arc::new(Self {
            pool,
            config,
            command_key,
            license_key,
            server_key,
            update_key,
            encryption_key,
            license_trust,
            password_slots: tokio::sync::Semaphore::new(4),
            dummy_hash,
        }))
    }
}

pub struct Session {
    pub user_id: String,
    pub tenant_id: String,
    pub role: Role,
    pub csrf: String,
    pub mfa_at: DateTime<Utc>,
    pub token_hash: String,
}
impl Session {
    pub fn actor(&self) -> Actor<'_> {
        Actor {
            user_id: &self.user_id,
            tenant_id: &self.tenant_id,
            role: self.role,
            mfa_verified_at: Some(self.mfa_at),
        }
    }
}
pub fn role(value: &str) -> Result<Role> {
    match value {
        "administrator" => Ok(Role::Administrator),
        "operator" => Ok(Role::Operator),
        "approver" => Ok(Role::Approver),
        "auditor" => Ok(Role::Auditor),
        _ => Err(Error::Invalid("rol")),
    }
}

pub async fn audit(
    tx: &mut Transaction<'_, Sqlite>,
    tenant: &str,
    actor: &str,
    event: &str,
    object: &str,
    now: i64,
) -> Result<()> {
    let previous: String = sqlx::query_scalar("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or_default();
    let hash = security::digest(
        serde_json::to_string(&(tenant, actor, event, object, now, &previous))?.as_bytes(),
    );
    sqlx::query("INSERT INTO audit(tenant_id,actor,event,object_id,at,previous_hash,hash) VALUES(?,?,?,?,?,?,?)")
        .bind(tenant).bind(actor).bind(event).bind(object).bind(now).bind(previous).bind(hash).execute(&mut **tx).await?;
    Ok(())
}
pub async fn rate(app: &App, scope: &str, limit: i64, seconds: i64, now: i64) -> Result<()> {
    sqlx::query("INSERT INTO rate_limits VALUES(?,?,1) ON CONFLICT(scope) DO UPDATE SET attempts=CASE WHEN window_start<=? THEN 1 ELSE attempts+1 END, window_start=CASE WHEN window_start<=? THEN excluded.window_start ELSE window_start END")
        .bind(security::digest(scope.as_bytes())).bind(now).bind(now-seconds).bind(now-seconds).execute(&app.pool).await?;
    let n: i64 = sqlx::query_scalar("SELECT attempts FROM rate_limits WHERE scope=?")
        .bind(security::digest(scope.as_bytes()))
        .fetch_one(&app.pool)
        .await?;
    if n > limit {
        return Err(Error::RateLimited);
    }
    Ok(())
}
pub async fn current_license(
    app: &App,
    tx: &mut Transaction<'_, Sqlite>,
    tenant: &str,
    now: DateTime<Utc>,
) -> Result<(SignedEnvelope, LicenseClaims, LicenseState, bool)> {
    let row = sqlx::query("SELECT envelope,revoked FROM licenses WHERE tenant_id=? ORDER BY issued_at DESC,rowid DESC LIMIT 1").bind(tenant).fetch_optional(&mut **tx).await?.ok_or(Error::Forbidden)?;
    let envelope: SignedEnvelope = serde_json::from_str(row.get("envelope"))?;
    let revoked: bool = row.get("revoked");
    let (claims, state) = verify_license(
        &envelope,
        &app.license_trust,
        &LicenseContext {
            tenant_id: tenant,
            now,
            online: true,
            revoked,
            last_trusted_online: Some(now),
        },
    )?;
    Ok((envelope, claims, state, revoked))
}
