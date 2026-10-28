//! Única frontera FFI Windows del workspace.
#[cfg(not(windows))]
use punishell_protocol::wire::Inventory;
use std::path::Path;
use thiserror::Error;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("Windows: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
    #[error("la operación requiere Windows")]
    WindowsRequired,
}
pub type Result<T> = std::result::Result<T, PlatformError>;

#[cfg(not(windows))]
pub fn inventory() -> Inventory {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|v| v.trim().into());
    let uptime_millis = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|v| v.split_whitespace().next()?.parse::<f64>().ok())
        .map(|n| (n * 1000.0) as u64)
        .unwrap_or(0);
    Inventory {
        hostname,
        uptime_millis,
        os_version: Some(std::env::consts::OS.into()),
        errors: vec!["Agente de consola Linux: campos nativos Windows no disponibles".into()],
        ..Inventory::default()
    }
}
#[cfg(not(windows))]
pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}
#[cfg(not(windows))]
pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}
#[cfg(not(windows))]
pub fn verify_authenticode(_path: &Path, _certificate: &str) -> Result<()> {
    Err(PlatformError::WindowsRequired)
}
#[cfg(not(windows))]
pub fn lock_interactive() -> Result<()> {
    Err(PlatformError::WindowsRequired)
}
#[cfg(not(windows))]
pub fn lock_desktop() -> Result<()> {
    Err(PlatformError::WindowsRequired)
}
#[cfg(not(windows))]
pub fn restart_service(_name: &str) -> Result<()> {
    Err(PlatformError::WindowsRequired)
}
#[cfg(not(windows))]
pub fn resume_bitlocker_protection(_mount_point: &str) -> Result<()> {
    Err(PlatformError::WindowsRequired)
}
#[cfg(not(windows))]
pub fn stop_agent_service() -> Result<()> {
    Err(PlatformError::WindowsRequired)
}
#[cfg(not(windows))]
pub fn start_agent_service() -> Result<()> {
    Err(PlatformError::WindowsRequired)
}

pub fn atomic_private_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| PlatformError::Other("archivo sin carpeta".into()))?;
    let mut file = tempfile::Builder::new()
        .prefix(".punishell-")
        .tempfile_in(parent)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    let (open, temp) = file.keep().map_err(|e| e.error)?;
    drop(open);
    #[cfg(windows)]
    {
        windows::replace_file(&temp, path)?;
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
