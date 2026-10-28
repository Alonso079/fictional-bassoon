//! Vigencia comercial con meses naturales, verificación Ed25519 y gracia acotada.
//!
//! El servidor debe proporcionar la revocación y el último check-in confiable.
//! Este módulo no consume códigos de activación ni persiste cupos en una DB.

use chrono::{DateTime, Duration, Months, Utc};
use punishell_protocol::{
    valid_id, verify_license_signature, Feature, LicenseClaims, ProtocolError, SignedEnvelope,
    TrustStore, PRODUCT, PROTOCOL_VERSION,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("meses fuera del rango 1..=120 o fecha no representable")]
    InvalidTerm,
    #[error("licencia mal formada, para otro producto o tenant")]
    InvalidLicense,
    #[error("reloj anterior al último contacto confiable")]
    ClockRollback,
    #[error("se requiere conexión para validar la licencia")]
    OnlineValidationRequired,
    #[error("licencia expirada o revocada")]
    InactiveLicense,
    #[error("funcionalidad no contratada")]
    FeatureNotLicensed,
    #[error("cupo de agentes agotado")]
    AgentLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseState {
    Active,
    GracePeriod { until: DateTime<Utc> },
    Expired,
    Revoked,
}

pub struct LicenseContext<'a> {
    pub tenant_id: &'a str,
    pub now: DateTime<Utc>,
    pub online: bool,
    /// Estado obtenido de una fuente autenticada; nunca del payload de un cliente.
    pub revoked: bool,
    pub last_trusted_online: Option<DateTime<Utc>>,
}

/// Calcula meses naturales UTC; el día se recorta al último día si no existe.
/// Ejemplo: 31 de agosto + 6 meses = último día de febrero.
pub fn subscription_expires_at(
    issued_at: DateTime<Utc>,
    months: u32,
) -> Result<DateTime<Utc>, LicenseError> {
    if !(1..=120).contains(&months) {
        return Err(LicenseError::InvalidTerm);
    }
    issued_at
        .checked_add_months(Months::new(months))
        .ok_or(LicenseError::InvalidTerm)
}

/// Valida firma y reglas. Para enrolar, además debe comprobarse cupo en transacción.
pub fn verify_license(
    envelope: &SignedEnvelope,
    keys: &TrustStore,
    context: &LicenseContext<'_>,
) -> Result<(LicenseClaims, LicenseState), LicenseError> {
    let claims = verify_license_signature(envelope, keys, context.now)?;
    let state = license_state(&claims, context)?;
    Ok((claims, state))
}

/// Aplicar solamente a claims cuya firma ya haya sido verificada.
pub fn license_state(
    claims: &LicenseClaims,
    context: &LicenseContext<'_>,
) -> Result<LicenseState, LicenseError> {
    if claims.protocol_version != PROTOCOL_VERSION
        || claims.product != PRODUCT
        || claims.tenant_id != context.tenant_id
        || !valid_id(&claims.license_id)
        || !valid_id(&claims.tenant_id)
        || !valid_id(&claims.plan)
        || claims.max_agents == 0
        || claims.features.is_empty()
        || claims.offline_grace_hours > 72
        || claims.expires_at <= claims.issued_at
        || context.now < claims.issued_at
    {
        return Err(LicenseError::InvalidLicense);
    }
    if context.revoked {
        return Ok(LicenseState::Revoked);
    }
    if context
        .last_trusted_online
        .is_some_and(|last| context.now < last)
    {
        return Err(LicenseError::ClockRollback);
    }
    if context.now >= claims.expires_at {
        return Ok(LicenseState::Expired);
    }
    if context.online {
        return Ok(LicenseState::Active);
    }
    let last = context
        .last_trusted_online
        .ok_or(LicenseError::OnlineValidationRequired)?;
    if last < claims.issued_at {
        return Err(LicenseError::OnlineValidationRequired);
    }
    let until = last
        .checked_add_signed(Duration::hours(i64::from(claims.offline_grace_hours)))
        .ok_or(LicenseError::InvalidLicense)?
        .min(claims.expires_at);
    if context.now >= until {
        return Err(LicenseError::OnlineValidationRequired);
    }
    Ok(LicenseState::GracePeriod { until })
}

/// La gracia offline permite inventario; las acciones administrativas requieren Active.
pub fn require_feature(
    claims: &LicenseClaims,
    state: LicenseState,
    feature: Feature,
) -> Result<(), LicenseError> {
    match state {
        LicenseState::Expired | LicenseState::Revoked => return Err(LicenseError::InactiveLicense),
        LicenseState::GracePeriod { .. } if feature != Feature::Inventory => {
            return Err(LicenseError::OnlineValidationRequired);
        }
        _ => {}
    }
    if !claims.features.contains(&feature) {
        return Err(LicenseError::FeatureNotLicensed);
    }
    Ok(())
}

/// El contador debe leerse y actualizarse dentro de la misma transacción SQL.
pub fn require_agent_capacity(
    claims: &LicenseClaims,
    state: LicenseState,
    enrolled_agents: u32,
) -> Result<(), LicenseError> {
    if state != LicenseState::Active {
        return Err(LicenseError::InactiveLicense);
    }
    if enrolled_agents >= claims.max_agents {
        return Err(LicenseError::AgentLimitReached);
    }
    Ok(())
}
