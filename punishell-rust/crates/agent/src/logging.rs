//! Bounded JSONL logs. Only typed operational metadata is accepted, never payloads.
use chrono::Utc;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};

const MAX_BYTES: u64 = 1024 * 1024;
const ARCHIVES: usize = 4;
const EXPORT_RECORDS: usize = 200;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Started,
    Stopped,
    ServiceFailed,
    EnrollmentStarted,
    EnrollmentFinished,
    RpcStarted,
    RpcSucceeded,
    RpcFailed,
    RetryScheduled,
    ActionStarted,
    ActionFinished,
    ActionFailed,
    ActionRejected,
    UpdateStaged,
    UpdateApplying,
    UpdateConfirmed,
    UpdateRollback,
    UpdateFailed,
    InstallStarted,
    InstallFilesCopied,
    InstallEnrollmentStarted,
    InstallServiceStarted,
    InstallCompleted,
    InstallFailed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Timeout,
    Dns,
    Tls,
    Connect,
    Http,
    Database,
    Platform,
    Protocol,
    License,
    Policy,
    Configuration,
    Io,
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub at: String,
    pub level: String,
    pub event: Event,
    pub version: String,
    pub agent_id: Option<String>,
    pub request_id: Option<String>,
    pub command_id: Option<String>,
    pub server_host: Option<String>,
    pub server_port: Option<u16>,
    pub failure: Option<Failure>,
    pub http_status: Option<u16>,
    pub os_error: Option<i32>,
    pub success: Option<bool>,
    pub duration_ms: Option<u64>,
    pub failures: Option<u32>,
    pub retry_seconds: Option<u64>,
}

impl Record {
    pub fn new(event: Event) -> Self {
        Self {
            at: Utc::now().to_rfc3339(),
            level: "info".into(),
            event,
            version: env!("CARGO_PKG_VERSION").into(),
            agent_id: None,
            request_id: None,
            command_id: None,
            server_host: None,
            server_port: None,
            failure: None,
            http_status: None,
            os_error: None,
            success: None,
            duration_ms: None,
            failures: None,
            retry_seconds: None,
        }
    }
    pub fn error(mut self, error: &crate::runtime::Error) -> Self {
        self.level = "error".into();
        self.failure = Some(classify(error));
        if let crate::runtime::Error::Http(e) = error {
            self.http_status = e.status().map(|s| s.as_u16());
        }
        self.os_error = match error {
            crate::runtime::Error::Io(e) => e.raw_os_error(),
            crate::runtime::Error::Platform(punishell_windows_platform::PlatformError::Io(e)) => {
                e.raw_os_error()
            }
            _ => None,
        };
        self
    }
    pub fn endpoint(mut self, url: &str) -> Self {
        if let Ok(url) = reqwest::Url::parse(url) {
            self.server_host = url.host_str().map(str::to_owned);
            self.server_port = url.port_or_known_default();
        }
        self
    }
    fn valid(&self) -> bool {
        self.at.len() <= 40
            && chrono::DateTime::parse_from_rfc3339(&self.at).is_ok()
            && matches!(self.level.as_str(), "info" | "warn" | "error")
            && self.version.len() <= 64
            && self.version.parse::<semver::Version>().is_ok()
            && self.server_host.as_ref().is_none_or(|h| {
                h.len() <= 253
                    && h.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c))
            })
            && [&self.agent_id, &self.request_id, &self.command_id]
                .iter()
                .all(|v| v.as_ref().is_none_or(|s| punishell_protocol::valid_id(s)))
    }
}

pub fn classify(error: &crate::runtime::Error) -> Failure {
    use crate::runtime::Error;
    match error {
        Error::Http(e) => {
            // Inspect the cause only for classification; never persist URLs or raw errors.
            let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(e);
            let mut description = String::new();
            while let Some(value) = cause {
                description.push_str(&value.to_string().to_ascii_lowercase());
                cause = value.source();
            }
            if e.is_timeout() {
                Failure::Timeout
            } else if description.contains("certificate") || description.contains("tls") {
                Failure::Tls
            } else if description.contains("dns") || description.contains("resolve") {
                Failure::Dns
            } else if e.is_connect() {
                Failure::Connect
            } else {
                Failure::Http
            }
        }
        Error::Database(_) => Failure::Database,
        Error::Platform(_) => Failure::Platform,
        Error::Protocol(_) => Failure::Protocol,
        Error::License(_) => Failure::License,
        Error::Domain(_) => Failure::Policy,
        Error::Invalid(_) => Failure::Configuration,
        Error::Io(_) => Failure::Io,
        Error::Json(_) => Failure::Json,
    }
}

fn open_private(path: &Path, append: bool) -> io::Result<File> {
    if path
        .symlink_metadata()
        .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
    {
        return Err(io::Error::other("log must be a regular file"));
    }
    let mut options = OpenOptions::new();
    options
        .create(true)
        .write(true)
        .append(append)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn lock(state: &Path) -> io::Result<File> {
    let dir = state.join("logs");
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let file = open_private(&dir.join("agent.lock"), false)?;
    file.lock_exclusive()?;
    Ok(file)
}

fn append(state: &Path, record: &Record, limit: u64) -> io::Result<()> {
    if !record.valid() {
        return Err(io::Error::other("invalid log metadata"));
    }
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    let _lock = lock(state)?;
    let dir = state.join("logs");
    let current = dir.join("agent.jsonl");
    if current
        .metadata()
        .is_ok_and(|m| m.len() + line.len() as u64 > limit)
    {
        let last = dir.join(format!("agent.{ARCHIVES}.jsonl"));
        if last.exists() {
            fs::remove_file(last)?;
        }
        for i in (1..ARCHIVES).rev() {
            let from = dir.join(format!("agent.{i}.jsonl"));
            if from.exists() {
                fs::rename(from, dir.join(format!("agent.{}.jsonl", i + 1)))?;
            }
        }
        fs::rename(&current, dir.join("agent.1.jsonl"))?;
    }
    let mut file = open_private(&current, true)?;
    file.write_all(&line)?;
    file.flush()
}

pub fn emit(state: &Path, record: Record) {
    if append(state, &record, MAX_BYTES).is_err() {
        // Logging failure must not repeat actions or prevent reporting a result.
        eprintln!("PuniShell: no se pudo escribir el log operativo");
    }
}

pub fn export(state: &Path, output: &Path) -> io::Result<()> {
    use std::io::Read;
    let _lock = lock(state)?;
    let mut records = VecDeque::new();
    let mut skipped = 0usize;
    let mut names: Vec<String> = (0..=ARCHIVES)
        .rev()
        .map(|index| {
            if index == 0 {
                "agent.jsonl".into()
            } else {
                format!("agent.{index}.jsonl")
            }
        })
        .collect();
    names.extend(["installer.1.jsonl".into(), "installer.jsonl".into()]);
    for name in names {
        let path = state.join("logs").join(name);
        let meta = match path.symlink_metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_BYTES {
            skipped += 1;
            continue;
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        for line in bytes.split(|v| *v == b'\n').filter(|v| !v.is_empty()) {
            match serde_json::from_slice::<Record>(line) {
                Ok(record) if record.valid() => {
                    let timestamp = chrono::DateTime::parse_from_rfc3339(&record.at)
                        .expect("validated timestamp")
                        .timestamp_millis();
                    let index = records.partition_point(|r: &Record| {
                        chrono::DateTime::parse_from_rfc3339(&r.at)
                            .expect("validated timestamp")
                            .timestamp_millis()
                            <= timestamp
                    });
                    records.insert(index, record);
                    if records.len() > EXPORT_RECORDS {
                        records.pop_front();
                    }
                }
                _ => skipped += 1,
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(
        &serde_json::json!({"schema_version":1,"generated_at":Utc::now().to_rfc3339(),"version":env!("CARGO_PKG_VERSION"),"platform":std::env::consts::OS,"skipped_entries":skipped,"events":records}),
    )?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotates_and_exports_only_valid_typed_metadata() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..80 {
            let mut record = Record::new(Event::RpcSucceeded);
            record.duration_ms = Some(i);
            append(dir.path(), &record, 1500).unwrap();
        }
        assert!(dir.path().join("logs/agent.4.jsonl").exists());
        for entry in fs::read_dir(dir.path().join("logs")).unwrap() {
            assert!(entry.unwrap().metadata().unwrap().len() <= 1500);
        }
        fs::write(dir.path().join("identity.dpapi"), "PRIVATE_KEY").unwrap();
        fs::write(dir.path().join("agent.json"), "ACTIVATION_CODE").unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(dir.path().join("logs/agent.jsonl"))
            .unwrap();
        writeln!(file, "{{\"password\":\"DO_NOT_EXPORT\"}}").unwrap();
        let output = dir.path().join("diagnostic.json");
        export(dir.path(), &output).unwrap();
        let text = fs::read_to_string(&output).unwrap();
        for secret in ["PRIVATE_KEY", "ACTIVATION_CODE", "DO_NOT_EXPORT"] {
            assert!(!text.contains(secret));
        }
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["skipped_entries"], 1);
        assert_eq!(
            value["events"].as_array().unwrap().last().unwrap()["duration_ms"],
            79
        );
        assert!(export(dir.path(), &output).is_err());
    }
    #[test]
    fn concurrent_writers_leave_complete_records_and_export_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let state = dir.path();
                scope.spawn(move || {
                    for _ in 0..100 {
                        append(state, &Record::new(Event::Started), MAX_BYTES).unwrap();
                    }
                });
            }
        });
        let text = fs::read_to_string(dir.path().join("logs/agent.jsonl")).unwrap();
        assert_eq!(text.lines().count(), 400);
        let output = dir.path().join("diagnostic.json");
        export(dir.path(), &output).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(value["events"].as_array().unwrap().len(), EXPORT_RECORDS);
    }

    #[test]
    fn errors_and_endpoint_never_persist_credentials_or_raw_messages() {
        let dir = tempfile::tempdir().unwrap();
        let error =
            crate::runtime::Error::Platform(punishell_windows_platform::PlatformError::Other(
                "PRIVATE_KEY Bearer SECRET_TOKEN".into(),
            ));
        let record = Record::new(Event::RpcFailed)
            .error(&error)
            .endpoint("https://user:password@192.168.1.50:8443/private?token=SECRET_TOKEN");
        append(dir.path(), &record, MAX_BYTES).unwrap();
        let text = fs::read_to_string(dir.path().join("logs/agent.jsonl")).unwrap();
        for secret in ["PRIVATE_KEY", "SECRET_TOKEN", "password", "private?"] {
            assert!(!text.contains(secret));
        }
        assert_eq!(record.failure, Some(Failure::Platform));
        assert_eq!(record.server_host.as_deref(), Some("192.168.1.50"));
        assert_eq!(record.server_port, Some(8443));
    }

    #[test]
    fn export_includes_installer_metadata_in_chronological_order() {
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), &Record::new(Event::RpcSucceeded), MAX_BYTES).unwrap();
        fs::write(dir.path().join("logs/installer.jsonl"),r#"{"at":"2020-01-01T00:00:00.0000000Z","level":"info","version":"0.1.0","event":"install_started"}"#).unwrap();
        let output = dir.path().join("diagnostic.json");
        export(dir.path(), &output).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(value["events"][0]["event"], "install_started");
        assert_eq!(value["events"][1]["event"], "rpc_succeeded");
    }

    #[test]
    fn unavailable_log_storage_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("not-a-directory");
        fs::write(&state, "existing file").unwrap();
        emit(&state, Record::new(Event::ActionFinished));
        assert_eq!(fs::read_to_string(state).unwrap(), "existing file");
    }

    #[cfg(unix)]
    #[test]
    fn exported_logs_are_private_and_symlinked_logs_are_excluded() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), &Record::new(Event::Started), MAX_BYTES).unwrap();
        assert_eq!(
            fs::metadata(dir.path().join("logs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let secret = dir.path().join("secret");
        fs::write(&secret, "PRIVATE_KEY").unwrap();
        symlink(&secret, dir.path().join("logs/installer.jsonl")).unwrap();
        let output = dir.path().join("export.json");
        export(dir.path(), &output).unwrap();
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!fs::read_to_string(output).unwrap().contains("PRIVATE_KEY"));
    }
}
