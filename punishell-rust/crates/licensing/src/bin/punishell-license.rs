//! Herramienta offline del proveedor. No distribuir junto al servidor cliente.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use punishell_licensing::{license_state, subscription_expires_at, LicenseContext};
use punishell_protocol::{
    generate_signing_key, sign_license, valid_id, wire::PublicKeyConfig, LicenseClaims, PRODUCT,
    PROTOCOL_VERSION,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Emisión offline de licencias — PuniShell SpA")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, default_value = "license-v1")]
        key_id: String,
    },
    Issue {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "license-v1")]
        key_id: String,
        #[arg(long)]
        tenant: String,
        #[arg(long, default_value = "monthly")]
        plan: String,
        #[arg(long, default_value_t = 1)]
        months: u32,
        #[arg(long, default_value_t = 25)]
        max_agents: u32,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "inventory,lock_workstation,wipe_data"
        )]
        features: Vec<String>,
        #[arg(long, default_value_t = 72)]
        offline_grace_hours: u16,
        #[arg(long)]
        output: PathBuf,
    },
}
fn write_new(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Init {
            key,
            public_key,
            key_id,
        } => {
            if !valid_id(&key_id) || key == public_key {
                return Err("key_id/rutas inválidos".into());
            }
            let signing = generate_signing_key();
            let public = PublicKeyConfig {
                key_id,
                public_key_b64: URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
                not_before: DateTime::from_timestamp(0, 0).ok_or("fecha")?,
                not_after: DateTime::from_timestamp(4_102_444_800, 0).ok_or("fecha")?,
            };
            write_new(&key, &signing.to_bytes())?;
            write_new(&public_key, &serde_json::to_vec_pretty(&public)?)?;
        }
        Command::Issue {
            key,
            key_id,
            tenant,
            plan,
            months,
            max_agents,
            features,
            offline_grace_hours,
            output,
        } => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if fs::metadata(&key)?.permissions().mode() & 0o077 != 0 {
                    return Err("clave requiere permisos 0600".into());
                }
            }
            let bytes = Zeroizing::new(fs::read(key)?);
            let signing = SigningKey::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "clave de 32 bytes")?,
            );
            let now = Utc::now();
            let claims = LicenseClaims {
                protocol_version: PROTOCOL_VERSION,
                license_id: URL_SAFE_NO_PAD
                    .encode(generate_signing_key().verifying_key().to_bytes()),
                tenant_id: tenant,
                product: PRODUCT.into(),
                plan,
                features: features
                    .into_iter()
                    .map(|v| serde_json::from_value(serde_json::Value::String(v)))
                    .collect::<Result<_, _>>()?,
                max_agents,
                issued_at: now,
                expires_at: subscription_expires_at(now, months)?,
                offline_grace_hours,
            };
            license_state(
                &claims,
                &LicenseContext {
                    tenant_id: &claims.tenant_id,
                    now,
                    online: true,
                    revoked: false,
                    last_trusted_online: None,
                },
            )?;
            write_new(
                &output,
                &serde_json::to_vec_pretty(&sign_license(&claims, &key_id, &signing)?)?,
            )?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
