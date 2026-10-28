//! Contrato HTTPS. Cada respuesta está ligada a la petición firmada exacta.
use crate::{Action, SignedEnvelope};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyConfig {
    pub key_id: String,
    pub public_key_b64: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub hostname: Option<String>,
    pub os_version: Option<String>,
    pub bios_serial: Option<String>,
    pub uptime_millis: u64,
    pub disk_total_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
    pub ram_installed_bytes: Option<u64>,
    pub ram_usable_bytes: Option<u64>,
    pub adapters: Vec<NetworkAdapter>,
    pub wifi: Vec<WifiInfo>,
    pub interactive_users: Vec<String>,
    pub defender_status: Option<String>,
    pub bitlocker_status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bitlocker_volumes: Vec<BitLockerVolume>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitLockerVolume {
    pub mount_point: Option<String>,
    pub protection_status: String,
    pub conversion_status: Option<String>,
    pub encryption_percentage: Option<u8>,
    pub encryption_method: Option<String>,
    pub lock_status: Option<String>,
    pub auto_unlock_enabled: Option<bool>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAdapter {
    pub name: String,
    pub mac: Option<String>,
    pub addresses: Vec<String>,
    pub active: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiInfo {
    pub ssid: String,
    pub bssid: String,
    pub signal_percent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentStart {
    pub tenant_id: String,
    pub activation_code: String,
    pub public_key_b64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub challenge_id: String,
    pub agent_id: String,
    pub tenant_id: String,
    pub nonce: String,
    pub public_key_b64: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRequest {
    pub agent_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub issued_at: DateTime<Utc>,
    pub operation: AgentOperation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AgentOperation {
    Enroll {
        challenge_id: String,
        nonce: String,
    },
    Heartbeat {
        inventory: Inventory,
        version: String,
    },
    Complete {
        command_id: String,
        lease_token: String,
        success: bool,
        output: String,
    },
    RotateKey {
        command_id: String,
        lease_token: String,
        public_key_b64: String,
        proof: SignedEnvelope,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerMessage {
    pub request_id: String,
    pub agent_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub license: SignedEnvelope,
    pub command: Option<SignedEnvelope>,
    pub lease_token: Option<String>,
    /// Se entrega una sola vez, dentro de TLS y de la respuesta firmada, para
    /// activar el cifrado de aplicación en el siguiente intercambio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_key_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationProof {
    pub agent_id: String,
    pub request_id: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub channel: String,
    pub version: String,
    pub platform: String,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub signer_certificate_sha256: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAction {
    pub agent_id: String,
    pub action: Action,
}
