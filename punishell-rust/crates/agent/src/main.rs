use clap::{Parser, Subcommand};
use punishell_agent::{
    runtime::{self, Agent},
    update,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Parser)]
#[command(
    version,
    about = "Agente de inventario y administración autorizada PuniShell Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Enroll {
        #[arg(long)]
        config: PathBuf,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        once: bool,
    },
    OfflineInventory {
        #[arg(long)]
        config: PathBuf,
    },
    Service,
    InstallService {
        #[arg(long)]
        config: PathBuf,
    },
    ApplyUpdate {
        #[arg(long)]
        config: PathBuf,
    },
    LockDesktop,
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Enroll { config } => {
            use std::io::Write;
            eprint!("Código de activación (entrada estándar): ");
            std::io::stderr().flush()?;
            let mut code = String::new();
            std::io::stdin().read_line(&mut code)?;
            let identity =
                runtime::enroll(runtime::read_config(&config)?, code.trim().into()).await?;
            println!("Agente activado: {identity}");
        }
        Command::Run { config, once } => {
            let agent = Agent::open(runtime::read_config(&config)?).await?;
            let stop = Arc::new(AtomicBool::new(false));
            let signal = stop.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal.store(true, Ordering::SeqCst);
            });
            agent.run(config, stop, once).await?;
        }
        Command::OfflineInventory { config } => {
            let agent = Agent::open(runtime::read_config(&config)?).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&runtime::offline_inventory(&agent).await?)?
            );
        }
        Command::Service => {
            #[cfg(windows)]
            {
                punishell_agent::service::start()?;
            }
            #[cfg(not(windows))]
            return Err("el servicio requiere Windows".into());
        }
        Command::InstallService { config } => {
            #[cfg(windows)]
            {
                punishell_agent::service::install(&config)?;
            }
            #[cfg(not(windows))]
            {
                let _ = config;
                return Err("la instalación del servicio requiere Windows".into());
            }
        }
        Command::ApplyUpdate { config } => update::apply(&config)?,
        Command::LockDesktop => punishell_windows_platform::lock_desktop()?,
    }
    Ok(())
}
