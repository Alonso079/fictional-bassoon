//! Permisos, parámetros y estados equivalentes a los flujos PHP actuales.
//! La identidad y MFA del actor se obtienen del servidor de sesiones autenticadas.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use punishell_protocol::{
    valid_id, verify_command_signature, Action, CommandClaims, Feature, ProtocolError,
    SignedEnvelope, TrustStore, PROTOCOL_VERSION,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Administrator,
    Operator,
    Approver,
    Auditor,
}

pub struct Actor<'a> {
    pub user_id: &'a str,
    pub tenant_id: &'a str,
    pub role: Role,
    pub mfa_verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandState {
    Pending,
    Approved,
    Rejected,
    Claimed,
    Running,
    Succeeded,
    Failed,
    Expired,
    Cancelled,
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("permisos o identidad insuficientes")]
    Forbidden,
    #[error("se requiere MFA reciente")]
    MfaRequired,
    #[error("el solicitante no puede aprobar su propia acción")]
    SelfApproval,
    #[error("transición de estado no permitida")]
    InvalidTransition,
    #[error("comando inválido, expirado o para otra instalación")]
    InvalidCommand,
    #[error("acción o parámetros fuera de política")]
    InvalidAction,
    #[error("falta aprobación para la acción administrativa")]
    ApprovalRequired,
}

pub struct CommandPolicy<'a> {
    pub tenant_id: &'a str,
    pub agent_id: &'a str,
    pub now: DateTime<Utc>,
    /// Conjunto derivado de una licencia validada, nunca del propio comando.
    pub enabled_features: &'a BTreeSet<Feature>,
    pub managed_services: &'a BTreeSet<String>,
    pub update_channels: &'a BTreeSet<String>,
}

/// Equivalente de solicitar_accion.php, con aislamiento explícito de tenant.
pub fn authorize_request(actor: &Actor<'_>, tenant_id: &str) -> Result<(), DomainError> {
    if actor.role != Role::Operator
        || actor.tenant_id != tenant_id
        || !valid_id(actor.user_id)
        || !valid_id(tenant_id)
    {
        return Err(DomainError::Forbidden);
    }
    Ok(())
}

/// Equivalente de autorizar_accion.php. La aprobación incluye doble control.
pub fn authorize_approval(
    actor: &Actor<'_>,
    tenant_id: &str,
    requester_id: &str,
    state: CommandState,
    now: DateTime<Utc>,
) -> Result<(), DomainError> {
    if actor.role != Role::Approver
        || actor.tenant_id != tenant_id
        || !valid_id(actor.user_id)
        || !valid_id(tenant_id)
        || !valid_id(requester_id)
    {
        return Err(DomainError::Forbidden);
    }
    if state != CommandState::Pending {
        return Err(DomainError::InvalidTransition);
    }
    if actor.user_id == requester_id {
        return Err(DomainError::SelfApproval);
    }
    let mfa = actor.mfa_verified_at.ok_or(DomainError::MfaRequired)?;
    if mfa > now || now.signed_duration_since(mfa) > Duration::minutes(5) {
        return Err(DomainError::MfaRequired);
    }
    Ok(())
}

pub fn transition(current: CommandState, next: CommandState) -> Result<CommandState, DomainError> {
    use CommandState::*;
    let allowed = match current {
        Pending => matches!(next, Approved | Rejected | Expired | Cancelled),
        Approved => matches!(next, Claimed | Expired | Cancelled),
        Claimed => matches!(next, Running | Failed | Expired | Cancelled),
        Running => matches!(next, Succeeded | Failed | Cancelled),
        _ => false,
    };
    if !allowed {
        return Err(DomainError::InvalidTransition);
    }
    Ok(next)
}

/// Verifica firma y semántica. Aún se requiere reservar command_id y nonce de
/// forma duradera y atómica antes de ejecutar; esta función no promete anti-replay.
pub fn validate_signed_command(
    envelope: &SignedEnvelope,
    keys: &TrustStore,
    policy: &CommandPolicy<'_>,
) -> Result<CommandClaims, DomainError> {
    let claims = verify_command_signature(envelope, keys, policy.now)?;
    validate_command(&claims, policy)?;
    Ok(claims)
}

pub fn validate_command(
    claims: &CommandClaims,
    policy: &CommandPolicy<'_>,
) -> Result<(), DomainError> {
    if claims.protocol_version != PROTOCOL_VERSION
        || !valid_id(&claims.command_id)
        || !valid_id(&claims.tenant_id)
        || !valid_id(&claims.agent_id)
        || claims.tenant_id != policy.tenant_id
        || claims.agent_id != policy.agent_id
        || claims.issued_at > policy.now
        || claims.expires_at <= policy.now
        || claims.expires_at <= claims.issued_at
        || claims.expires_at.signed_duration_since(claims.issued_at) > Duration::minutes(5)
        || claims.nonce.len() != 32
        || !claims.nonce.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(DomainError::InvalidCommand);
    }
    if !policy
        .enabled_features
        .contains(&claims.action.required_feature())
    {
        return Err(DomainError::Forbidden);
    }
    if !matches!(claims.action, Action::CollectInventory)
        && !claims.approval_id.as_deref().is_some_and(valid_id)
    {
        return Err(DomainError::ApprovalRequired);
    }
    validate_action(&claims.action, policy)
}

fn validate_action(action: &Action, policy: &CommandPolicy<'_>) -> Result<(), DomainError> {
    match action {
        Action::DiagnosticBundle {
            max_bytes,
            timeout_seconds,
        } if *max_bytes == 0
            || *max_bytes > 1_048_576
            || *timeout_seconds == 0
            || *timeout_seconds > 60 =>
        {
            Err(DomainError::InvalidAction)
        }
        Action::RestartManagedService { service_name }
            if !policy.managed_services.contains(service_name) || !valid_id(service_name) =>
        {
            Err(DomainError::InvalidAction)
        }
        Action::RequestUpdate { channel }
            if !policy.update_channels.contains(channel) || !valid_id(channel) =>
        {
            Err(DomainError::InvalidAction)
        }
        Action::ResumeBitLockerProtection { mount_point }
            if mount_point.len() != 2
                || !mount_point.as_bytes()[0].is_ascii_uppercase()
                || mount_point.as_bytes()[1] != b':' =>
        {
            Err(DomainError::InvalidAction)
        }
        _ => Ok(()),
    }
}
