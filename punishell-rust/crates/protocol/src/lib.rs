//! Contratos tipados y firmas. Este crate no abre sockets ni ejecuta procesos.
//!
//! La firma cubre los bytes exactos transportados, el propósito y el key_id.
//! El payload JSON se analiza después de verificar la firma. No es JSON JCS.

use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
pub mod wire;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
pub const MAX_ENCRYPTED_BYTES: usize = 32 * 1024;
pub const PRODUCT: &str = "punishell-mdm";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Inventory,
    LockWorkstation,
    Diagnostics,
    ManageServices,
    Updates,
    RotateIdentity,
    ManageBitLocker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Action {
    CollectInventory,
    LockWorkstation,
    DiagnosticBundle {
        max_bytes: u32,
        timeout_seconds: u16,
    },
    RestartManagedService {
        service_name: String,
    },
    RequestUpdate {
        channel: String,
    },
    RotateAgentKey,
    ResumeBitLockerProtection {
        mount_point: String,
    },
}

impl Action {
    pub fn required_feature(&self) -> Feature {
        match self {
            Self::CollectInventory => Feature::Inventory,
            Self::LockWorkstation => Feature::LockWorkstation,
            Self::DiagnosticBundle { .. } => Feature::Diagnostics,
            Self::RestartManagedService { .. } => Feature::ManageServices,
            Self::RequestUpdate { .. } => Feature::Updates,
            Self::RotateAgentKey => Feature::RotateIdentity,
            Self::ResumeBitLockerProtection { .. } => Feature::ManageBitLocker,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandClaims {
    pub protocol_version: u16,
    pub command_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Identificador aleatorio de al menos 128 bits representado en hexadecimal.
    pub nonce: String,
    /// Referencia al evento de aprobación del servidor; no es una firma humana.
    pub approval_id: Option<String>,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseClaims {
    pub protocol_version: u16,
    pub license_id: String,
    pub tenant_id: String,
    pub product: String,
    pub plan: String,
    pub features: BTreeSet<Feature>,
    pub max_agents: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub offline_grace_hours: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub key_id: String,
    pub payload_b64: String,
    pub signature_b64: String,
}

/// Sobre de aplicación cifrado. TLS sigue siendo obligatorio; esta capa evita
/// exponer el mensaje firmado a proxies, colas y registros intermedios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub protocol_version: u16,
    pub agent_id: String,
    pub key_id: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentWireEnvelope {
    Encrypted(EncryptedEnvelope),
    Signed(SignedEnvelope),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionDirection {
    AgentToServer,
    ServerToAgent,
}

impl EncryptionDirection {
    fn label(self) -> &'static [u8] {
        match self {
            Self::AgentToServer => b"PUNISHELL-AGENT-TO-SERVER-AES256GCM-V1\0",
            Self::ServerToAgent => b"PUNISHELL-SERVER-TO-AGENT-AES256GCM-V1\0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Command,
    License,
    Device,
    Server,
    Update,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Command => b"PUNISHELL-COMMAND-V1\0",
            Self::License => b"PUNISHELL-LICENSE-V1\0",
            Self::Device => b"PUNISHELL-DEVICE-V1\0",
            Self::Server => b"PUNISHELL-SERVER-V1\0",
            Self::Update => b"PUNISHELL-UPDATE-V1\0",
        }
    }
}

/// La API debe cargar este conjunto desde configuración de confianza, no del mensaje.
pub struct TrustedKey {
    pub key: VerifyingKey,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub revoked: bool,
}

pub type TrustStore = BTreeMap<String, TrustedKey>;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("identificador inválido")]
    InvalidIdentifier,
    #[error("payload demasiado grande")]
    PayloadTooLarge,
    #[error("codificación base64url inválida")]
    InvalidEncoding,
    #[error("clave desconocida, revocada o fuera de vigencia")]
    UntrustedKey,
    #[error("firma inválida")]
    InvalidSignature,
    #[error("payload JSON inválido: {0}")]
    InvalidPayload(#[from] serde_json::Error),
    #[error("sobre cifrado inválido")]
    InvalidEncryption,
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Generación segura para enrolamiento o provisión; la persistencia es externa.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn signing_bytes(purpose: Purpose, key_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(64 + key_id.len() + payload.len());
    data.extend_from_slice(purpose.label());
    data.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    data.extend_from_slice(key_id.as_bytes());
    data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    data.extend_from_slice(payload);
    data
}

fn encryption_aad(direction: EncryptionDirection, agent_id: &str, key_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + agent_id.len() + key_id.len());
    aad.extend_from_slice(direction.label());
    aad.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    aad.extend_from_slice(&(agent_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(agent_id.as_bytes());
    aad.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

pub fn encrypt_payload<T: Serialize>(
    value: &T,
    direction: EncryptionDirection,
    agent_id: &str,
    key_id: &str,
    key: &[u8; 32],
) -> Result<EncryptedEnvelope, ProtocolError> {
    if !valid_id(agent_id) || !valid_id(key_id) {
        return Err(ProtocolError::InvalidIdentifier);
    }
    let plaintext = serde_json::to_vec(value)?;
    if plaintext.len() > MAX_ENCRYPTED_BYTES {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &encryption_aad(direction, agent_id, key_id),
            },
        )
        .map_err(|_| ProtocolError::InvalidEncryption)?;
    Ok(EncryptedEnvelope {
        protocol_version: PROTOCOL_VERSION,
        agent_id: agent_id.into(),
        key_id: key_id.into(),
        nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_payload<T: DeserializeOwned>(
    envelope: &EncryptedEnvelope,
    direction: EncryptionDirection,
    expected_agent_id: &str,
    expected_key_id: &str,
    key: &[u8; 32],
) -> Result<T, ProtocolError> {
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.agent_id != expected_agent_id
        || envelope.key_id != expected_key_id
        || !valid_id(&envelope.agent_id)
        || !valid_id(&envelope.key_id)
        || envelope.nonce_b64.len() != 16
        || envelope.ciphertext_b64.len() > (MAX_ENCRYPTED_BYTES + 16).div_ceil(3) * 4
    {
        return Err(ProtocolError::InvalidEncryption);
    }
    let nonce: [u8; 12] = URL_SAFE_NO_PAD
        .decode(&envelope.nonce_b64)
        .map_err(|_| ProtocolError::InvalidEncryption)?
        .try_into()
        .map_err(|_| ProtocolError::InvalidEncryption)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| ProtocolError::InvalidEncryption)?;
    let plaintext = Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &encryption_aad(direction, expected_agent_id, expected_key_id),
            },
        )
        .map_err(|_| ProtocolError::InvalidEncryption)?;
    if plaintext.len() > MAX_ENCRYPTED_BYTES {
        return Err(ProtocolError::PayloadTooLarge);
    }
    Ok(serde_json::from_slice(&plaintext)?)
}

pub fn sign_payload<T: Serialize>(
    claims: &T,
    purpose: Purpose,
    key_id: &str,
    key: &SigningKey,
) -> Result<SignedEnvelope, ProtocolError> {
    if !valid_id(key_id) {
        return Err(ProtocolError::InvalidIdentifier);
    }
    let payload = serde_json::to_vec(claims)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let signature = key.sign(&signing_bytes(purpose, key_id, &payload));
    Ok(SignedEnvelope {
        key_id: key_id.into(),
        payload_b64: URL_SAFE_NO_PAD.encode(payload),
        signature_b64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

pub fn verify_payload<T: DeserializeOwned>(
    envelope: &SignedEnvelope,
    purpose: Purpose,
    keys: &TrustStore,
    now: DateTime<Utc>,
) -> Result<T, ProtocolError> {
    if !valid_id(&envelope.key_id) {
        return Err(ProtocolError::InvalidIdentifier);
    }
    let max_encoded = MAX_PAYLOAD_BYTES.div_ceil(3) * 4;
    if envelope.payload_b64.len() > max_encoded || envelope.signature_b64.len() != 86 {
        return Err(ProtocolError::InvalidEncoding);
    }
    let trusted = keys
        .get(&envelope.key_id)
        .ok_or(ProtocolError::UntrustedKey)?;
    if trusted.revoked || now < trusted.not_before || now >= trusted.not_after {
        return Err(ProtocolError::UntrustedKey);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(&envelope.payload_b64)
        .map_err(|_| ProtocolError::InvalidEncoding)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.signature_b64)
        .map_err(|_| ProtocolError::InvalidEncoding)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ProtocolError::InvalidEncoding)?;
    trusted
        .key
        .verify_strict(
            &signing_bytes(purpose, &envelope.key_id, &payload),
            &signature,
        )
        .map_err(|_| ProtocolError::InvalidSignature)?;
    Ok(serde_json::from_slice(&payload)?)
}

/// Ejecutar exclusivamente en el servidor después de autorizar la acción.
pub fn sign_command(
    claims: &CommandClaims,
    key_id: &str,
    key: &SigningKey,
) -> Result<SignedEnvelope, ProtocolError> {
    sign_payload(claims, Purpose::Command, key_id, key)
}

/// Verifica autenticidad; la validación operativa pertenece a domain.
pub fn verify_command_signature(
    envelope: &SignedEnvelope,
    keys: &TrustStore,
    now: DateTime<Utc>,
) -> Result<CommandClaims, ProtocolError> {
    verify_payload(envelope, Purpose::Command, keys, now)
}

/// Usar una clave de licenciamiento distinta de la clave de comandos.
pub fn sign_license(
    claims: &LicenseClaims,
    key_id: &str,
    key: &SigningKey,
) -> Result<SignedEnvelope, ProtocolError> {
    sign_payload(claims, Purpose::License, key_id, key)
}

pub fn verify_license_signature(
    envelope: &SignedEnvelope,
    keys: &TrustStore,
    now: DateTime<Utc>,
) -> Result<LicenseClaims, ProtocolError> {
    verify_payload(envelope, Purpose::License, keys, now)
}
