use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use punishell_protocol::{generate_signing_key, sign_payload, wire::UpdateManifest, Purpose};
use punishell_server::{
    api, security,
    store::{
        self, public_config, write_private, App, Config, Error, Result, COMMAND_KEY, LICENSE_KEY,
        SERVER_KEY, UPDATE_KEY,
    },
};
use sqlx::Row;
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Parser)]
#[command(version, about = "Servidor HTTPS y administración de PuniShell Rust")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        public_url: String,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, default_value = "main")]
        tenant: String,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    AddUser {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        role: String,
    },
    AddTenant {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
    },
    ResetPassword {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        username: String,
    },
    PublishUpdate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        signer_certificate_sha256: String,
    },
    VerifyAudit {
        #[arg(long)]
        config: PathBuf,
    },
}
fn password() -> Result<String> {
    if let Ok(value) = std::env::var("PUNISHELL_PASSWORD") {
        return Ok(value);
    }
    eprintln!(
        "Contraseña nueva (entrada estándar; usar PUNISHELL_PASSWORD desde un gestor de secretos):"
    );
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\n', '\r']).into())
}
fn config(path: &PathBuf) -> Result<Config> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Init {
            config: config_path,
            state_dir,
            public_url,
            certificate,
            private_key,
            username,
            tenant,
        } => {
            if !punishell_protocol::valid_id(&tenant) {
                return Err(Error::Invalid("tenant"));
            }
            if state_dir.exists() || config_path.exists() {
                return Err(Error::Conflict);
            }
            let pass = password()?;
            security::password_hash(&pass)?;
            std::fs::create_dir_all(&state_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
            }
            for name in ["command", "license", "server", "update", "encryption"] {
                write_private(
                    &state_dir.join(format!("{name}.key")),
                    &generate_signing_key().to_bytes(),
                )?;
            }
            let config = Config {
                state_dir: std::fs::canonicalize(state_dir)?,
                bind: "127.0.0.1:8443".into(),
                public_url,
                tls_certificate: std::fs::canonicalize(certificate)?,
                tls_private_key: std::fs::canonicalize(private_key)?,
                managed_services: BTreeSet::new(),
                update_channels: BTreeSet::from(["stable".into()]),
            };
            let app = App::open(config.clone()).await?;
            sqlx::query("INSERT INTO tenants VALUES(?,?,?)")
                .bind(&tenant)
                .bind(&tenant)
                .bind(Utc::now().timestamp())
                .execute(&app.pool)
                .await?;
            let user = api::add_user(&app, &tenant, &username, &pass, "administrator").await?;
            write_private(&config_path, &serde_json::to_vec_pretty(&config)?)?;
            let roots = serde_json::json!({"server":public_config(SERVER_KEY,&app.server_key),"command":public_config(COMMAND_KEY,&app.command_key),"license":public_config(LICENSE_KEY,&app.license_key),"update":public_config(UPDATE_KEY,&app.update_key)});
            write_private(
                &app.config.state_dir.join("trust.json"),
                &serde_json::to_vec_pretty(&roots)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&user)?);
            eprintln!(
                "Provisionar el secreto MFA mostrado una sola vez. Trust público: {}",
                app.config.state_dir.join("trust.json").display()
            );
        }
        Command::Serve { config: path } => {
            let config = config(&path)?;
            let address = config.bind.parse().map_err(|_| Error::Invalid("bind"))?;
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &config.tls_certificate,
                &config.tls_private_key,
            )
            .await?;
            let app = App::open(config).await?;
            let handle = axum_server::Handle::new();
            let shutdown = handle.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            eprintln!("PuniShell HTTPS en {address}; no hay listener HTTP.");
            axum_server::bind_rustls(address, tls)
                .handle(handle)
                .serve(api::router(app).into_make_service())
                .await?;
        }
        Command::AddUser {
            config: path,
            tenant,
            username,
            role,
        } => {
            let app = App::open(config(&path)?).await?;
            println!(
                "{}",
                api::add_user(&app, &tenant, &username, &password()?, &role).await?
            );
        }
        Command::AddTenant {
            config: path,
            id,
            name,
        } => {
            if !punishell_protocol::valid_id(&id) || name.is_empty() || name.len() > 128 {
                return Err(Error::Invalid("tenant"));
            }
            let app = App::open(config(&path)?).await?;
            let mut tx = app.pool.begin().await?;
            sqlx::query("INSERT INTO tenants VALUES(?,?,?)")
                .bind(&id)
                .bind(name)
                .bind(Utc::now().timestamp())
                .execute(&mut *tx)
                .await?;
            store::audit(
                &mut tx,
                &id,
                "local-admin",
                "tenant_created",
                &id,
                Utc::now().timestamp(),
            )
            .await?;
            tx.commit().await?;
        }
        Command::ResetPassword {
            config: path,
            username,
        } => {
            let app = App::open(config(&path)?).await?;
            let user: String =
                sqlx::query_scalar("SELECT id FROM users WHERE username=? AND disabled=0")
                    .bind(username)
                    .fetch_one(&app.pool)
                    .await?;
            let token = security::token();
            sqlx::query("INSERT INTO password_resets VALUES(?,?,?,NULL)")
                .bind(security::digest(token.as_bytes()))
                .bind(user)
                .bind((Utc::now() + Duration::minutes(15)).timestamp())
                .execute(&app.pool)
                .await?;
            println!("{token}");
            eprintln!("Token de un uso, vence en 15 minutos; el usuario aún necesita su TOTP.");
        }
        Command::PublishUpdate {
            config: path,
            file,
            channel,
            version,
            signer_certificate_sha256,
        } => {
            if signer_certificate_sha256.len() != 64
                || !signer_certificate_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
                || !punishell_protocol::valid_id(&version)
            {
                return Err(Error::Invalid("certificado/version"));
            }
            let app = App::open(config(&path)?).await?;
            if !app.config.update_channels.contains(&channel) {
                return Err(Error::Invalid("canal"));
            }
            let parsed = version
                .parse::<semver::Version>()
                .map_err(|_| Error::Invalid("versión semver"))?;
            if let Some(raw) =
                sqlx::query_scalar::<_, String>("SELECT envelope FROM updates WHERE channel=?")
                    .bind(&channel)
                    .fetch_optional(&app.pool)
                    .await?
            {
                let envelope: punishell_protocol::SignedEnvelope = serde_json::from_str(&raw)?;
                use base64::Engine;
                let old: UpdateManifest = serde_json::from_slice(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(envelope.payload_b64)
                        .map_err(|_| Error::Invalid("manifiesto"))?,
                )?;
                if parsed
                    <= old
                        .version
                        .parse::<semver::Version>()
                        .map_err(|_| Error::Invalid("versión previa"))?
                {
                    return Err(Error::Invalid("actualización debe aumentar versión"));
                }
            }
            let data = std::fs::read(file)?;
            if data.len() > 64 * 1024 * 1024 || !data.starts_with(b"MZ") {
                return Err(Error::Invalid("EXE PE Windows, máximo 64 MiB"));
            }
            let name = format!("punishell-agent-{version}.exe");
            let dir = app.config.state_dir.join("updates");
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(&name);
            write_private(&path, &data)?;
            let now = Utc::now();
            let manifest = UpdateManifest {
                channel: channel.clone(),
                version,
                platform: "x86_64-pc-windows-msvc".into(),
                path: format!("/downloads/{name}"),
                sha256: security::digest(&data),
                size: data.len() as u64,
                signer_certificate_sha256: signer_certificate_sha256.to_lowercase(),
                issued_at: now,
                expires_at: now + Duration::days(30),
            };
            let envelope = sign_payload(&manifest, Purpose::Update, UPDATE_KEY, &app.update_key)?;
            let mut tx = app.pool.begin().await?;
            sqlx::query("INSERT INTO updates VALUES(?,?,?,?) ON CONFLICT(channel) DO UPDATE SET envelope=excluded.envelope,file_path=excluded.file_path,filename=excluded.filename").bind(&channel).bind(serde_json::to_string(&envelope)?).bind(path.to_string_lossy().to_string()).bind(name).execute(&mut *tx).await?;
            store::audit(
                &mut tx,
                "system",
                "local-admin",
                "update_published",
                &channel,
                now.timestamp(),
            )
            .await?;
            tx.commit().await?;
        }
        Command::VerifyAudit { config: path } => {
            let app = App::open(config(&path)?).await?;
            let rows = sqlx::query("SELECT * FROM audit ORDER BY id")
                .fetch_all(&app.pool)
                .await?;
            let mut previous = String::new();
            for r in &rows {
                let hash = security::digest(
                    serde_json::to_string(&(
                        r.get::<String, _>("tenant_id"),
                        r.get::<String, _>("actor"),
                        r.get::<String, _>("event"),
                        r.get::<String, _>("object_id"),
                        r.get::<i64, _>("at"),
                        &previous,
                    ))?
                    .as_bytes(),
                );
                if r.get::<String, _>("previous_hash") != previous
                    || r.get::<String, _>("hash") != hash
                {
                    return Err(Error::Invalid("cadena de auditoría alterada"));
                }
                previous = hash;
            }
            println!("{} eventos verificados; último hash {}. Guardar este checkpoint fuera del servidor.",rows.len(),previous);
        }
    }
    Ok(())
}
