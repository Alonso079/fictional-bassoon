use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures_util::StreamExt;
use punishell_domain::{validate_signed_command, CommandPolicy};
use punishell_licensing::{require_feature, verify_license, LicenseContext, LicenseState};
use punishell_protocol::{
    decrypt_payload, encrypt_payload, generate_signing_key, sign_payload, valid_id, verify_payload,
    wire::*, Action, AgentWireEnvelope, EncryptionDirection, Feature, Purpose, SignedEnvelope,
    TrustStore, TrustedKey,
};
use punishell_windows_platform as platform;
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, SqlitePool,
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuración: {0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Database(#[from] sqlx::Error),
    #[error("{0}")]
    Http(#[from] reqwest::Error),
    #[error("{0}")]
    Platform(#[from] platform::PlatformError),
    #[error("{0}")]
    Protocol(#[from] punishell_protocol::ProtocolError),
    #[error("{0}")]
    License(#[from] punishell_licensing::LicenseError),
    #[error("{0}")]
    Domain(#[from] punishell_domain::DomainError),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server_url: String,
    pub tenant_id: String,
    pub state_dir: PathBuf,
    pub installed_executable: PathBuf,
    pub server_keys: Vec<PublicKeyConfig>,
    pub command_keys: Vec<PublicKeyConfig>,
    pub license_keys: Vec<PublicKeyConfig>,
    pub update_keys: Vec<PublicKeyConfig>,
    pub ca_certificate: Option<PathBuf>,
    pub managed_services: BTreeSet<String>,
    pub update_channels: BTreeSet<String>,
    pub signer_certificates: BTreeSet<String>,
    pub poll_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub agent_id: String,
    pub private_key_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_key_b64: Option<String>,
}
pub struct Agent {
    pub config: Config,
    pub client: reqwest::Client,
    pub pool: SqlitePool,
    pub identity: Identity,
    pub key: SigningKey,
    pub server_trust: TrustStore,
    pub command_trust: TrustStore,
    pub license_trust: TrustStore,
    pub update_trust: TrustStore,
}
pub fn token() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn id() -> String {
    token().replace('-', "a").replace('_', "b")
}
pub fn read_config(path: &Path) -> Result<Config> {
    let c: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    c.validate()?;
    Ok(c)
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.server_url).map_err(|_| Error::Invalid("URL"))?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || self.server_url.ends_with('/')
            || !valid_id(&self.tenant_id)
            || !self.state_dir.is_absolute()
            || !self.installed_executable.is_absolute()
            || !(10..=3600).contains(&self.poll_seconds)
        {
            return Err(Error::Invalid("HTTPS/tenant/ruta/polling"));
        }
        for keys in [
            &self.server_keys,
            &self.command_keys,
            &self.license_keys,
            &self.update_keys,
        ] {
            trust(keys)?;
            if keys.is_empty() {
                return Err(Error::Invalid("trust store vacío"));
            }
        }
        if self
            .signer_certificates
            .iter()
            .any(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Error::Invalid("certificados SHA-256"));
        }
        Ok(())
    }
    pub fn client(&self) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        if let Some(path) = &self.ca_certificate {
            builder = builder
                .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
        }
        Ok(builder.build()?)
    }
}
pub fn instance_lock(config: &Config) -> Result<std::fs::File> {
    use fs2::FileExt;
    std::fs::create_dir_all(&config.state_dir)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(config.state_dir.join("agent.lock"))?;
    file.try_lock_exclusive()
        .map_err(|_| Error::Invalid("otra instancia del agente está activa"))?;
    Ok(file)
}
pub fn trust(configs: &[PublicKeyConfig]) -> Result<TrustStore> {
    let mut keys = TrustStore::new();
    for c in configs {
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&c.public_key_b64)
            .map_err(|_| Error::Invalid("clave pública"))?
            .try_into()
            .map_err(|_| Error::Invalid("clave pública"))?;
        if !valid_id(&c.key_id) || c.not_before >= c.not_after || keys.contains_key(&c.key_id) {
            return Err(Error::Invalid("trust store"));
        }
        keys.insert(
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
    Ok(keys)
}
fn signing_key(encoded: &str) -> Result<SigningKey> {
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Invalid("identidad"))?,
    );
    let key: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invalid("identidad"))?;
    Ok(SigningKey::from_bytes(key))
}
fn transport_key(identity: &Identity) -> Result<Option<(String, [u8; 32])>> {
    match (&identity.transport_key_id, &identity.transport_key_b64) {
        (None, None) => Ok(None),
        (Some(key_id), Some(encoded)) if valid_id(key_id) => {
            let key = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| Error::Invalid("clave de transporte"))?
                .try_into()
                .map_err(|_| Error::Invalid("clave de transporte"))?;
            Ok(Some((key_id.clone(), key)))
        }
        _ => Err(Error::Invalid("identidad de transporte incompleta")),
    }
}
pub fn save_identity(config: &Config, identity: &Identity) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(identity)?);
    platform::atomic_private_write(
        &config.state_dir.join("identity.dpapi"),
        &platform::protect(&bytes)?,
    )?;
    Ok(())
}
fn read_identity(config: &Config) -> Result<Identity> {
    let bytes = Zeroizing::new(platform::unprotect(&std::fs::read(
        config.state_dir.join("identity.dpapi"),
    )?)?);
    Ok(serde_json::from_slice(&bytes)?)
}
pub async fn response_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T> {
    let response = response.error_for_status()?;
    if response.content_length().is_some_and(|v| v > 32768) {
        return Err(Error::Invalid("respuesta demasiado grande"));
    }
    let mut stream = response.bytes_stream();
    let mut data = vec![];
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if data.len() + chunk.len() > 32768 {
            return Err(Error::Invalid("respuesta demasiado grande"));
        }
        data.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&data)?)
}

impl Agent {
    pub async fn open(config: Config) -> Result<Self> {
        config.validate()?;
        let identity = read_identity(&config)?;
        if !valid_id(&identity.agent_id) {
            return Err(Error::Invalid("agent_id"));
        }
        let key = signing_key(&identity.private_key_b64)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(config.state_dir.join("journal.db"))
                    .create_if_missing(true)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                    .synchronous(sqlx::sqlite::SqliteSynchronous::Full),
            )
            .await?;
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS meta(name TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS pending(id INTEGER PRIMARY KEY CHECK(id=1),envelope TEXT NOT NULL); CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,state TEXT NOT NULL,envelope TEXT NOT NULL,lease TEXT NOT NULL,success INTEGER,output TEXT);") .execute(&pool).await?;
        let server_trust = trust(&config.server_keys)?;
        let command_trust = trust(&config.command_keys)?;
        let license_trust = trust(&config.license_keys)?;
        let update_trust = trust(&config.update_keys)?;
        let client = config.client()?;
        Ok(Self {
            config,
            client,
            pool,
            identity,
            key,
            server_trust,
            command_trust,
            license_trust,
            update_trust,
        })
    }
    pub async fn prepare(&self, mut operation: AgentOperation) -> Result<SignedEnvelope> {
        if let Some(raw) =
            sqlx::query_scalar::<_, String>("SELECT envelope FROM pending WHERE id=1")
                .fetch_optional(&self.pool)
                .await?
        {
            return Ok(serde_json::from_str(&raw)?);
        }
        let mut tx = self.pool.begin().await?;
        let last = sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE name='sequence'")
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or_else(|| "0".into())
            .parse::<u64>()
            .map_err(|_| Error::Invalid("secuencia"))?;
        let sequence = last
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Error::Invalid("secuencia agotada"))?;
        let request_id = id();
        if let AgentOperation::RotateKey {
            public_key_b64,
            proof,
            ..
        } = &mut operation
        {
            let secret = Zeroizing::new(platform::unprotect(&std::fs::read(
                self.config.state_dir.join("rotation.dpapi"),
            )?)?);
            let key = SigningKey::from_bytes(
                secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Invalid("rotación"))?,
            );
            *proof = sign_payload(
                &RotationProof {
                    agent_id: self.identity.agent_id.clone(),
                    request_id: request_id.clone(),
                    public_key_b64: public_key_b64.clone(),
                },
                Purpose::Device,
                &self.identity.agent_id,
                &key,
            )?;
        }
        let request = DeviceRequest {
            agent_id: self.identity.agent_id.clone(),
            request_id,
            sequence,
            issued_at: Utc::now(),
            operation,
        };
        let envelope = sign_payload(
            &request,
            Purpose::Device,
            &self.identity.agent_id,
            &self.key,
        )?;
        sqlx::query("INSERT INTO meta VALUES('sequence',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value").bind(sequence.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO pending VALUES(1,?)")
            .bind(serde_json::to_string(&envelope)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(envelope)
    }
    pub async fn rpc(&mut self, operation: AgentOperation) -> Result<ServerMessage> {
        let envelope = self.prepare(operation).await?;
        let request: DeviceRequest = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&envelope.payload_b64)
                .map_err(|_| Error::Invalid("petición"))?,
        )?;
        // La rotación conserva el mismo sobre hasta recibir el recibo servidor:
        // perderlo después del cambio de clave dejaría al dispositivo huérfano.
        if Utc::now() - request.issued_at > chrono::Duration::minutes(2)
            && !matches!(
                request.operation,
                AgentOperation::RotateKey { .. } | AgentOperation::Enroll { .. }
            )
        {
            sqlx::query("DELETE FROM pending WHERE id=1")
                .execute(&self.pool)
                .await?;
            return Err(Error::Invalid(
                "petición expirada; se reconciliará en el siguiente contacto",
            ));
        }
        let current_transport = transport_key(&self.identity)?;
        let wire = match &current_transport {
            Some((key_id, key)) => AgentWireEnvelope::Encrypted(encrypt_payload(
                &envelope,
                EncryptionDirection::AgentToServer,
                &self.identity.agent_id,
                key_id,
                key,
            )?),
            None => AgentWireEnvelope::Signed(envelope.clone()),
        };
        let reply_wire: AgentWireEnvelope = response_json(
            self.client
                .post(format!("{}/api/v1/agent", self.config.server_url))
                .header("x-punishell-transport", "aes256gcm-v1")
                .json(&wire)
                .send()
                .await?,
        )
        .await?;
        let reply = match (&current_transport, reply_wire) {
            (Some((key_id, key)), AgentWireEnvelope::Encrypted(encrypted)) => decrypt_payload(
                &encrypted,
                EncryptionDirection::ServerToAgent,
                &self.identity.agent_id,
                key_id,
                key,
            )?,
            (None, AgentWireEnvelope::Signed(signed)) => signed,
            _ => return Err(Error::Invalid("respuesta con cifrado inesperado")),
        };
        let now = Utc::now();
        let message: ServerMessage =
            verify_payload(&reply, Purpose::Server, &self.server_trust, now)?;
        if message.request_id != request.request_id
            || message.agent_id != self.identity.agent_id
            || message.issued_at > now + chrono::Duration::seconds(30)
            || message.expires_at <= now
        {
            return Err(Error::Invalid("respuesta no correlacionada o expirada"));
        }
        let (license, state) = verify_license(
            &message.license,
            &self.license_trust,
            &LicenseContext {
                tenant_id: &self.config.tenant_id,
                now,
                online: true,
                revoked: message.revoked,
                last_trusted_online: self.last_online().await?,
            },
        )?;
        match (&message.transport_key_id, &message.transport_key_b64) {
            (Some(key_id), Some(encoded)) if current_transport.is_none() && valid_id(key_id) => {
                let _: [u8; 32] = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| Error::Invalid("clave de transporte"))?
                    .try_into()
                    .map_err(|_| Error::Invalid("clave de transporte"))?;
                self.identity.transport_key_id = Some(key_id.clone());
                self.identity.transport_key_b64 = Some(encoded.clone());
                save_identity(&self.config, &self.identity)?;
            }
            (None, None) => {}
            _ => return Err(Error::Invalid("provisión de transporte inválida")),
        }
        if let Some(command) = &message.command {
            let features = if state == LicenseState::Active {
                license.features.clone()
            } else {
                BTreeSet::new()
            };
            let claims = validate_signed_command(
                command,
                &self.command_trust,
                &CommandPolicy {
                    tenant_id: &self.config.tenant_id,
                    agent_id: &self.identity.agent_id,
                    now,
                    enabled_features: &features,
                    managed_services: &self.config.managed_services,
                    update_channels: &self.config.update_channels,
                },
            )?;
            let lease = message
                .lease_token
                .as_ref()
                .filter(|v| v.len() == 43)
                .ok_or(Error::Invalid("lease"))?;
            let mut tx = self.pool.begin().await?;
            let previous = sqlx::query("SELECT envelope,lease FROM actions WHERE id=?")
                .bind(&claims.command_id)
                .fetch_optional(&mut *tx)
                .await?;
            if let Some(row) = previous {
                if row.get::<String, _>("envelope") != serde_json::to_string(command)?
                    || row.get::<String, _>("lease") != *lease
                {
                    return Err(Error::Invalid("comando repetido diferente"));
                }
            } else {
                sqlx::query(
                    "INSERT INTO actions(id,nonce,state,envelope,lease) VALUES(?,?,'ready',?,?)",
                )
                .bind(&claims.command_id)
                .bind(&claims.nonce)
                .bind(serde_json::to_string(command)?)
                .bind(lease)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        }
        if let AgentOperation::RotateKey { command_id, .. } = &request.operation {
            let secret = Zeroizing::new(platform::unprotect(&std::fs::read(
                self.config.state_dir.join("rotation.dpapi"),
            )?)?);
            let key = SigningKey::from_bytes(
                secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Invalid("rotación"))?,
            );
            self.identity.private_key_b64 = URL_SAFE_NO_PAD.encode(key.to_bytes());
            save_identity(&self.config, &self.identity)?;
            self.key = key;
            self.finish_local(command_id, true, "identity rotated")
                .await?;
        }
        if let AgentOperation::Complete { command_id, .. } = &request.operation {
            sqlx::query("UPDATE actions SET state='reported' WHERE id=? AND state='complete'")
                .bind(command_id)
                .execute(&self.pool)
                .await?;
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO meta VALUES('server_message',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value").bind(serde_json::to_string(&reply)?).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM pending WHERE id=1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        platform::atomic_private_write(
            &self.config.state_dir.join("health.json"),
            &serde_json::to_vec(
                &serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"at":now.timestamp()}),
            )?,
        )?;
        Ok(message)
    }
    pub async fn last_online(&self) -> Result<Option<chrono::DateTime<Utc>>> {
        if let Some(raw) =
            sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE name='server_message'")
                .fetch_optional(&self.pool)
                .await?
        {
            let envelope: SignedEnvelope = serde_json::from_str(&raw)?;
            let message: ServerMessage =
                verify_payload(&envelope, Purpose::Server, &self.server_trust, Utc::now())?;
            return Ok(Some(message.issued_at));
        }
        Ok(None)
    }
    pub async fn finish_local(&self, id: &str, success: bool, output: &str) -> Result<()> {
        let mut output = output.to_string();
        while output.len() > 7800 {
            output.pop();
        }
        sqlx::query("UPDATE actions SET state='complete',success=?,output=? WHERE id=?")
            .bind(success)
            .bind(output)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn outbox(&self) -> Result<Option<AgentOperation>> {
        let row=sqlx::query("SELECT id,lease,success,output FROM actions WHERE state='complete' ORDER BY rowid LIMIT 1").fetch_optional(&self.pool).await?;
        Ok(row.map(|r| AgentOperation::Complete {
            command_id: r.get("id"),
            lease_token: r.get("lease"),
            success: r.get("success"),
            output: r.get("output"),
        }))
    }
    async fn execute(&mut self, config_path: &Path) -> Result<()> {
        let Some(row) = sqlx::query(
            "SELECT id,envelope,lease FROM actions WHERE state='ready' ORDER BY rowid LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(());
        };
        let id: String = row.get("id");
        let envelope: SignedEnvelope = serde_json::from_str(row.get("envelope"))?;
        let now = Utc::now();
        let raw: String = sqlx::query_scalar("SELECT value FROM meta WHERE name='server_message'")
            .fetch_one(&self.pool)
            .await?;
        let server: ServerMessage = verify_payload(
            &serde_json::from_str::<SignedEnvelope>(&raw)?,
            Purpose::Server,
            &self.server_trust,
            now,
        )?;
        let online = self.last_online().await?;
        let (license, state) = verify_license(
            &server.license,
            &self.license_trust,
            &LicenseContext {
                tenant_id: &self.config.tenant_id,
                now,
                online: true,
                revoked: server.revoked,
                last_trusted_online: online,
            },
        )?;
        let features = if state == LicenseState::Active {
            license.features
        } else {
            BTreeSet::new()
        };
        let claims = match validate_signed_command(
            &envelope,
            &self.command_trust,
            &CommandPolicy {
                tenant_id: &self.config.tenant_id,
                agent_id: &self.identity.agent_id,
                now,
                enabled_features: &features,
                managed_services: &self.config.managed_services,
                update_channels: &self.config.update_channels,
            },
        ) {
            Ok(c) => c,
            Err(e) => {
                self.finish_local(&id, false, &e.to_string()).await?;
                return Ok(());
            }
        };
        sqlx::query("UPDATE actions SET state='running' WHERE id=? AND state='ready'")
            .bind(&id)
            .execute(&self.pool)
            .await?;
        let result: Result<String> = match claims.action {
            Action::CollectInventory => Ok(serde_json::to_string(&platform::inventory())?),
            Action::DiagnosticBundle { max_bytes, .. } => {
                let mut value = serde_json::to_string_pretty(&platform::inventory())?;
                while value.len() > max_bytes as usize {
                    value.pop();
                }
                Ok(value)
            }
            Action::LockWorkstation => platform::lock_interactive()
                .map(|_| "Sesión interactiva bloqueada".into())
                .map_err(Error::from),
            Action::RestartManagedService { service_name } => {
                platform::restart_service(&service_name)
                    .map(|_| "Servicio reiniciado".into())
                    .map_err(Error::from)
            }
            Action::RequestUpdate { channel } => crate::update::stage(self, &channel, config_path)
                .await
                .map(|_| {
                    "Actualización verificada y preparada; comprobar versión posterior".into()
                }),
            Action::RotateAgentKey => {
                let key = generate_signing_key();
                platform::atomic_private_write(
                    &self.config.state_dir.join("rotation.dpapi"),
                    &platform::protect(&key.to_bytes())?,
                )?;
                let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
                // prepare sustituye esta firma inicial por la prueba ligada al request_id persistido.
                let proof = sign_payload(
                    &RotationProof {
                        agent_id: self.identity.agent_id.clone(),
                        request_id: "prepare".into(),
                        public_key_b64: public.clone(),
                    },
                    Purpose::Device,
                    &self.identity.agent_id,
                    &key,
                )?;
                self.rpc(AgentOperation::RotateKey {
                    command_id: id.clone(),
                    lease_token: row.get("lease"),
                    public_key_b64: public,
                    proof,
                })
                .await
                .map(|_| "identity rotated".into())
            }
            Action::ResumeBitLockerProtection { mount_point } => {
                platform::resume_bitlocker_protection(&mount_point)
                    .map(|_| format!("Protección BitLocker reanudada en {mount_point}"))
                    .map_err(Error::from)
            }
        };
        match result {
            Ok(output) => self.finish_local(&id, true, &output).await?,
            Err(error) => self.finish_local(&id, false, &error.to_string()).await?,
        }
        Ok(())
    }
    pub async fn run(
        mut self,
        config_path: PathBuf,
        stop: Arc<AtomicBool>,
        once: bool,
    ) -> Result<()> {
        let _instance = instance_lock(&self.config)?;
        // No se repite una acción cuyo efecto no pudo confirmarse tras un reinicio.
        sqlx::query("UPDATE actions SET state='complete',success=0,output='Resultado incierto tras reinicio; no se volvió a ejecutar' WHERE state='running'").execute(&self.pool).await?;
        let mut failures = 0u32;
        while !stop.load(Ordering::Relaxed) {
            let operation = if let Some(outbox) = self.outbox().await? {
                outbox
            } else {
                AgentOperation::Heartbeat {
                    inventory: platform::inventory(),
                    version: env!("CARGO_PKG_VERSION").into(),
                }
            };
            match self.rpc(operation).await {
                Ok(_) => {
                    failures = 0;
                    if let Err(error) = self.execute(&config_path).await {
                        if once {
                            return Err(error);
                        }
                        eprintln!("Acción: {error}");
                    }
                }
                Err(error) => {
                    if once {
                        return Err(error);
                    }
                    failures = failures.saturating_add(1);
                    eprintln!("Check-in rechazado/fallido: {error}");
                }
            }
            if once {
                break;
            }
            let delay = self
                .config
                .poll_seconds
                .saturating_mul(1u64 << failures.min(5))
                .min(300);
            let jitter = (token().as_bytes()[0] as u64) % 3;
            for _ in 0..(delay + jitter) * 2 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        Ok(())
    }
}

pub async fn enroll(config: Config, code: String) -> Result<String> {
    config.validate()?;
    std::fs::create_dir_all(&config.state_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let _instance = instance_lock(&config)?;
    let key = if config.state_dir.join("identity.dpapi").exists() {
        let mut agent = Agent::open(config.clone()).await?;
        if let Some(raw) =
            sqlx::query_scalar::<_, String>("SELECT envelope FROM pending WHERE id=1")
                .fetch_optional(&agent.pool)
                .await?
        {
            let envelope: SignedEnvelope = serde_json::from_str(&raw)?;
            let request: DeviceRequest = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(&envelope.payload_b64)
                    .map_err(|_| Error::Invalid("enrolamiento pendiente"))?,
            )?;
            if !matches!(request.operation, AgentOperation::Enroll { .. }) {
                return Err(Error::Invalid(
                    "operación pendiente distinta del enrolamiento",
                ));
            }
            match agent
                .rpc(AgentOperation::Heartbeat {
                    inventory: Inventory::default(),
                    version: env!("CARGO_PKG_VERSION").into(),
                })
                .await
            {
                Ok(_) => return Ok(agent.identity.agent_id),
                Err(Error::Http(error))
                    if error.status() == Some(reqwest::StatusCode::UNAUTHORIZED)
                        && Utc::now() - request.issued_at > chrono::Duration::minutes(2) =>
                {
                    sqlx::query("DELETE FROM pending WHERE id=1")
                        .execute(&agent.pool)
                        .await?;
                }
                Err(error) => return Err(error),
            }
        }
        if agent.last_online().await?.is_some() {
            return Err(Error::Invalid("agente ya activado"));
        }
        agent.key.clone()
    } else {
        generate_signing_key()
    };
    let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let client = config.client()?;
    let envelope: SignedEnvelope = response_json(
        client
            .post(format!("{}/api/v1/enrollment/start", config.server_url))
            .json(&EnrollmentStart {
                tenant_id: config.tenant_id.clone(),
                activation_code: code,
                public_key_b64: public.clone(),
            })
            .send()
            .await?,
    )
    .await?;
    let now = Utc::now();
    let challenge: EnrollmentChallenge = verify_payload(
        &envelope,
        Purpose::Server,
        &trust(&config.server_keys)?,
        now,
    )?;
    if challenge.tenant_id != config.tenant_id
        || challenge.public_key_b64 != public
        || challenge.expires_at <= now
        || challenge.issued_at > now + chrono::Duration::seconds(30)
        || !valid_id(&challenge.agent_id)
    {
        return Err(Error::Invalid("challenge"));
    }
    save_identity(
        &config,
        &Identity {
            agent_id: challenge.agent_id.clone(),
            private_key_b64: URL_SAFE_NO_PAD.encode(key.to_bytes()),
            transport_key_id: None,
            transport_key_b64: None,
        },
    )?;
    let mut agent = Agent::open(config).await?;
    agent
        .rpc(AgentOperation::Enroll {
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
        })
        .await?;
    Ok(challenge.agent_id)
}

/// Inventario offline únicamente si la última respuesta firmada permite la gracia.
pub async fn offline_inventory(agent: &Agent) -> Result<Inventory> {
    let raw: String = sqlx::query_scalar("SELECT value FROM meta WHERE name='server_message'")
        .fetch_one(&agent.pool)
        .await?;
    let now = Utc::now();
    let message: ServerMessage = verify_payload(
        &serde_json::from_str::<SignedEnvelope>(&raw)?,
        Purpose::Server,
        &agent.server_trust,
        now,
    )?;
    let (license, state) = verify_license(
        &message.license,
        &agent.license_trust,
        &LicenseContext {
            tenant_id: &agent.config.tenant_id,
            now,
            online: false,
            revoked: message.revoked,
            last_trusted_online: Some(message.issued_at),
        },
    )?;
    require_feature(&license, state, Feature::Inventory)?;
    Ok(platform::inventory())
}
