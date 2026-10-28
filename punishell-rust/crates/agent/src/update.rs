//! Actualización con manifiesto Ed25519, SHA-256 y Authenticode fijado.
use crate::runtime::{self, Agent, Error, Result};
#[cfg(windows)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use punishell_protocol::{verify_payload, wire::UpdateManifest, Purpose, SignedEnvelope};
use punishell_windows_platform as platform;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Duration, Instant};

const MAX_UPDATE: u64 = 64 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Staged {
    manifest: SignedEnvelope,
    target: PathBuf,
    artifact: PathBuf,
}

fn valid_manifest(agent: &Agent, signed: &SignedEnvelope, channel: &str) -> Result<UpdateManifest> {
    let manifest: UpdateManifest =
        verify_payload(signed, Purpose::Update, &agent.update_trust, Utc::now())?;
    let previous = env!("CARGO_PKG_VERSION")
        .parse::<semver::Version>()
        .map_err(|_| Error::Invalid("versión actual"))?;
    let next = manifest
        .version
        .parse::<semver::Version>()
        .map_err(|_| Error::Invalid("versión nueva"))?;
    if next <= previous
        || manifest.channel != channel
        || manifest.platform != "x86_64-pc-windows-msvc"
        || manifest.issued_at > Utc::now() + chrono::Duration::seconds(30)
        || manifest.expires_at <= Utc::now()
        || manifest.size == 0
        || manifest.size > MAX_UPDATE
        || manifest.sha256.len() != 64
        || !manifest.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || !agent
            .config
            .signer_certificates
            .contains(&manifest.signer_certificate_sha256)
        || !manifest.path.starts_with("/downloads/")
        || manifest.path[11..].is_empty()
        || !manifest.path[11..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Error::Invalid("manifiesto de actualización"));
    }
    Ok(manifest)
}
#[cfg(windows)]
fn verify_artifact(path: &Path, manifest: &UpdateManifest) -> Result<()> {
    let meta = std::fs::metadata(path)?;
    if meta.len() != manifest.size || meta.len() > MAX_UPDATE {
        return Err(Error::Invalid("tamaño de actualización"));
    }
    let bytes = std::fs::read(path)?;
    if !bytes.starts_with(b"MZ") || format!("{:x}", Sha256::digest(&bytes)) != manifest.sha256 {
        return Err(Error::Invalid("hash PE de actualización"));
    }
    platform::verify_authenticode(path, &manifest.signer_certificate_sha256)?;
    Ok(())
}
pub async fn stage(agent: &Agent, channel: &str, config_path: &Path) -> Result<()> {
    if !agent.config.update_channels.contains(channel) {
        return Err(Error::Invalid("canal no permitido"));
    }
    let envelope: SignedEnvelope = runtime::response_json(
        agent
            .client
            .get(format!(
                "{}/api/v1/updates/{channel}",
                agent.config.server_url
            ))
            .send()
            .await?,
    )
    .await?;
    let manifest = valid_manifest(agent, &envelope, channel)?;
    let uri = format!("{}{}", agent.config.server_url, manifest.path);
    let response = agent.client.get(uri).send().await?.error_for_status()?;
    if response.content_length().is_some_and(|n| n > MAX_UPDATE) {
        return Err(Error::Invalid("descarga demasiado grande"));
    }
    use futures_util::StreamExt;
    use std::io::Write;
    let artifact = agent.config.state_dir.join("update-staged.exe");
    let mut file = tempfile::Builder::new()
        .prefix("download-")
        .suffix(".exe")
        .tempfile_in(&agent.config.state_dir)?;
    let mut stream = response.bytes_stream();
    let mut total = 0u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total = total
            .checked_add(chunk.len() as u64)
            .filter(|n| *n <= MAX_UPDATE)
            .ok_or(Error::Invalid("descarga demasiado grande"))?;
        hash.update(&chunk);
        file.as_file_mut().write_all(&chunk)?;
    }
    file.as_file().sync_all()?;
    if total != manifest.size || format!("{:x}", hash.finalize()) != manifest.sha256 {
        return Err(Error::Invalid("descarga alterada"));
    }
    platform::verify_authenticode(file.path(), &manifest.signer_certificate_sha256)?;
    let part = file.into_temp_path().keep().map_err(|e| e.error)?;
    #[cfg(windows)]
    platform::replace_file(&part, &artifact)?;
    #[cfg(not(windows))]
    std::fs::rename(&part, &artifact)?;
    let target = std::env::current_exe()?;
    if target != agent.config.installed_executable {
        return Err(Error::Invalid("ejecutable instalado distinto al proceso"));
    }
    let state = Staged {
        manifest: envelope,
        target,
        artifact,
    };
    platform::atomic_private_write(
        &agent.config.state_dir.join("update.json"),
        &serde_json::to_vec(&state)?,
    )?;
    #[cfg(windows)]
    {
        let helper = agent
            .config
            .state_dir
            .join(format!("update-helper-{}.exe", runtime::id()));
        // El helper corre fuera del EXE que se reemplaza; no se ejecuta material descargado.
        std::fs::copy(std::env::current_exe()?, &helper)?;
        std::process::Command::new(helper)
            .arg("apply-update")
            .arg("--config")
            .arg(config_path)
            .spawn()?;
    }
    #[cfg(not(windows))]
    {
        let _ = config_path;
        Err(Error::Invalid(
            "actualización automática requiere servicio Windows",
        ))
    }
    #[cfg(windows)]
    Ok(())
}

pub fn apply(config_path: &Path) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = config_path;
        Err(Error::Invalid("actualización automática requiere Windows"))
    }
    #[cfg(windows)]
    {
        let config = runtime::read_config(config_path)?;
        let bytes = std::fs::read(config.state_dir.join("update.json"))?;
        let staged: Staged = serde_json::from_slice(&bytes)?;
        let channel = staged.manifest_channel()?;
        if !config.update_channels.contains(&channel) {
            return Err(Error::Invalid("canal"));
        }
        let keys = runtime::trust(&config.update_keys)?;
        let manifest: UpdateManifest =
            verify_payload(&staged.manifest, Purpose::Update, &keys, Utc::now())?;
        let current = env!("CARGO_PKG_VERSION")
            .parse::<semver::Version>()
            .map_err(|_| Error::Invalid("versión actual"))?;
        if manifest.channel != channel
            || manifest.issued_at > Utc::now() + chrono::Duration::seconds(30)
            || manifest.expires_at <= Utc::now()
            || manifest
                .version
                .parse::<semver::Version>()
                .map_err(|_| Error::Invalid("versión nueva"))?
                <= current
            || !config
                .signer_certificates
                .contains(&manifest.signer_certificate_sha256)
            || staged.artifact != config.state_dir.join("update-staged.exe")
            || staged.target != config.installed_executable
        {
            return Err(Error::Invalid("plan de actualización"));
        }
        verify_artifact(&staged.artifact, &manifest)?;
        let backup = config.state_dir.join("agent-backup.exe");
        std::fs::copy(&staged.target, &backup)?;
        let replacement = config.state_dir.join("update-replacement.exe");
        std::fs::copy(&staged.artifact, &replacement)?;
        verify_artifact(&replacement, &manifest)?;
        std::thread::sleep(Duration::from_secs(3));
        platform::stop_agent_service()?;
        if let Err(error) = platform::replace_file(&replacement, &staged.target) {
            let _ = platform::start_agent_service();
            return Err(error.into());
        }
        let start_at = Utc::now().timestamp();
        let started = platform::start_agent_service();
        if started.is_ok() {
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                if let Ok(bytes) = std::fs::read(config.state_dir.join("health.json")) {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if value["version"] == manifest.version
                            && value["at"].as_i64().is_some_and(|t| t >= start_at)
                        {
                            return Ok(());
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        let _ = platform::stop_agent_service();
        let restore = config.state_dir.join("update-restore.exe");
        std::fs::copy(backup, &restore)?;
        platform::replace_file(&restore, &staged.target)?;
        platform::start_agent_service()?;
        Err(Error::Invalid(
            "actualización revertida: el nuevo agente no informó estado saludable",
        ))
    }
}

impl Staged {
    #[cfg(windows)]
    fn manifest_channel(&self) -> Result<String> {
        let raw = URL_SAFE_NO_PAD
            .decode(&self.manifest.payload_b64)
            .map_err(|_| Error::Invalid("manifiesto"))?;
        let manifest: UpdateManifest = serde_json::from_slice(&raw)?;
        Ok(manifest.channel)
    }
}
