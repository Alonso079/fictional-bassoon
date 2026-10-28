use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use punishell_licensing::*;
use punishell_protocol::*;

fn at(value: &str) -> DateTime<Utc> {
    value.parse().unwrap()
}
fn now() -> DateTime<Utc> {
    at("2026-10-11T12:00:00Z")
}
fn claims() -> LicenseClaims {
    LicenseClaims {
        protocol_version: PROTOCOL_VERSION,
        license_id: "license-1".into(),
        tenant_id: "tenant-1".into(),
        product: PRODUCT.into(),
        plan: "starter_6m".into(),
        features: BTreeSet::from([Feature::Inventory, Feature::LockWorkstation]),
        max_agents: 25,
        issued_at: now(),
        expires_at: subscription_expires_at(now(), 6).unwrap(),
        offline_grace_hours: 72,
    }
}
fn context() -> LicenseContext<'static> {
    LicenseContext {
        tenant_id: "tenant-1",
        now: now(),
        online: true,
        revoked: false,
        last_trusted_online: Some(now()),
    }
}

#[test]
fn six_twelve_and_twenty_four_months_use_calendar_months() {
    for (months, expected) in [
        (6, "2027-04-11T12:00:00Z"),
        (12, "2027-10-11T12:00:00Z"),
        (24, "2028-10-11T12:00:00Z"),
    ] {
        assert_eq!(
            subscription_expires_at(now(), months).unwrap(),
            at(expected)
        );
    }
    assert!(subscription_expires_at(now(), 0).is_err());
    assert!(subscription_expires_at(now(), 121).is_err());
}

#[test]
fn end_of_month_and_leap_year_are_explicit() {
    assert_eq!(
        subscription_expires_at(at("2026-08-31T12:00:00Z"), 6).unwrap(),
        at("2027-02-28T12:00:00Z")
    );
    assert_eq!(
        subscription_expires_at(at("2027-08-31T12:00:00Z"), 6).unwrap(),
        at("2028-02-29T12:00:00Z")
    );
}

#[test]
fn verified_license_roundtrips_through_the_signature_layer() {
    let key = generate_signing_key();
    let keys = BTreeMap::from([(
        "licensing-key".into(),
        TrustedKey {
            key: key.verifying_key(),
            not_before: now(),
            not_after: now() + Duration::days(365),
            revoked: false,
        },
    )]);
    let license = claims();
    let envelope = sign_license(&license, "licensing-key", &key).unwrap();
    assert_eq!(
        verify_license(&envelope, &keys, &context()).unwrap(),
        (license, LicenseState::Active)
    );
}

#[test]
fn expiry_is_inclusive_and_grace_does_not_extend_a_subscription() {
    let mut context = context();
    context.now = claims().expires_at;
    context.online = false;
    context.last_trusted_online = Some(context.now - Duration::hours(1));
    assert_eq!(
        license_state(&claims(), &context).unwrap(),
        LicenseState::Expired
    );
    assert!(require_feature(&claims(), LicenseState::Expired, Feature::Inventory).is_err());
}

#[test]
fn offline_window_is_bounded_by_both_checkin_and_expiry() {
    let mut context = context();
    context.online = false;
    context.now += Duration::hours(71);
    let state = license_state(&claims(), &context).unwrap();
    assert_eq!(
        state,
        LicenseState::GracePeriod {
            until: now() + Duration::hours(72)
        }
    );
    assert!(require_feature(&claims(), state, Feature::Inventory).is_ok());
    assert!(matches!(
        require_feature(&claims(), state, Feature::LockWorkstation),
        Err(LicenseError::OnlineValidationRequired)
    ));
    context.now += Duration::hours(1);
    assert!(matches!(
        license_state(&claims(), &context),
        Err(LicenseError::OnlineValidationRequired)
    ));
    context.now = claims().expires_at - Duration::hours(1);
    context.last_trusted_online = Some(context.now);
    assert_eq!(
        license_state(&claims(), &context).unwrap(),
        LicenseState::GracePeriod {
            until: claims().expires_at
        }
    );
}

#[test]
fn wrong_tenant_revocation_and_clock_rollback_are_rejected() {
    let mut context = context();
    context.tenant_id = "tenant-2";
    assert!(matches!(
        license_state(&claims(), &context),
        Err(LicenseError::InvalidLicense)
    ));
    context.tenant_id = "tenant-1";
    context.revoked = true;
    assert_eq!(
        license_state(&claims(), &context).unwrap(),
        LicenseState::Revoked
    );
    context.revoked = false;
    context.last_trusted_online = Some(now() + Duration::seconds(1));
    assert!(matches!(
        license_state(&claims(), &context),
        Err(LicenseError::ClockRollback)
    ));
}

#[test]
fn first_offline_activation_and_excessive_grace_are_rejected() {
    let mut context = context();
    context.online = false;
    context.last_trusted_online = None;
    assert!(matches!(
        license_state(&claims(), &context),
        Err(LicenseError::OnlineValidationRequired)
    ));
    let mut license = claims();
    license.offline_grace_hours = 73;
    assert!(matches!(
        license_state(&license, &context),
        Err(LicenseError::InvalidLicense)
    ));
}

#[test]
fn licensed_features_and_capacity_are_checked_at_the_boundary() {
    assert!(matches!(
        require_feature(&claims(), LicenseState::Active, Feature::Updates),
        Err(LicenseError::FeatureNotLicensed)
    ));
    assert!(require_agent_capacity(&claims(), LicenseState::Active, 24).is_ok());
    assert!(matches!(
        require_agent_capacity(&claims(), LicenseState::Active, 25),
        Err(LicenseError::AgentLimitReached)
    ));
    assert!(require_agent_capacity(&claims(), LicenseState::Revoked, 0).is_err());
}
