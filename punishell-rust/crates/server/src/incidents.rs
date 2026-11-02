//! Persistent operational findings. Unknown or stale inventory cannot prove recovery.
use crate::security;
use crate::store::{audit, Result};
use punishell_protocol::wire::Inventory;
use sqlx::{Row, Sqlite, Transaction};

async fn observe(
    tx: &mut Transaction<'_, Sqlite>,
    agent: &str,
    tenant: &str,
    kind: &str,
    observation: Option<(bool, &str, String, i64)>,
    now: i64,
) -> Result<()> {
    let Some((failing, severity, detail, evidence_at)) = observation else {
        return Ok(());
    };
    let active = sqlx::query("SELECT id,evidence_at FROM incidents WHERE agent_id=? AND kind=? AND state IN ('open','acknowledged')")
        .bind(agent).bind(kind).fetch_optional(&mut **tx).await?;
    match (active, failing) {
        (Some(row), true) => {
            sqlx::query(
                "UPDATE incidents SET last_seen=?,evidence_at=?,detail=?,severity=? WHERE id=?",
            )
            .bind(now)
            .bind(evidence_at)
            .bind(detail)
            .bind(severity)
            .bind(row.get::<String, _>("id"))
            .execute(&mut **tx)
            .await?;
        }
        (Some(row), false) if evidence_at > row.get::<i64, _>("evidence_at") => {
            let id: String = row.get("id");
            sqlx::query("UPDATE incidents SET state='resolved',resolved_at=?,evidence_at=?,detail=? WHERE id=?")
                .bind(now).bind(evidence_at).bind(detail).bind(&id).execute(&mut **tx).await?;
            audit(tx, tenant, "incident-engine", "incident_resolved", &id, now).await?;
        }
        (None, true) => {
            let id = security::id();
            sqlx::query("INSERT INTO incidents(id,tenant_id,agent_id,kind,severity,state,first_seen,last_seen,evidence_at,detail) VALUES(?,?,?,?,?,'open',?,?,?,?)")
                .bind(&id).bind(tenant).bind(agent).bind(kind).bind(severity)
                .bind(now).bind(now).bind(evidence_at).bind(detail).execute(&mut **tx).await?;
            audit(tx, tenant, "incident-engine", "incident_opened", &id, now).await?;
        }
        _ => {}
    }
    Ok(())
}

pub async fn evaluate(tx: &mut Transaction<'_, Sqlite>, now: i64) -> Result<()> {
    let agents =
        sqlx::query("SELECT id,tenant_id,last_seen,inventory,revoked FROM agents ORDER BY id")
            .fetch_all(&mut **tx)
            .await?;
    for row in agents {
        let agent: &str = row.get("id");
        let tenant: &str = row.get("tenant_id");
        if row.get::<bool, _>("revoked") {
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM incidents WHERE agent_id=? AND state IN ('open','acknowledged')",
            )
            .bind(agent)
            .fetch_all(&mut **tx)
            .await?;
            for id in ids {
                sqlx::query("UPDATE incidents SET state='resolved',resolved_at=?,detail='Equipo revocado; fuera de monitoreo' WHERE id=?")
                    .bind(now).bind(&id).execute(&mut **tx).await?;
                audit(
                    tx,
                    tenant,
                    "incident-engine",
                    "incident_closed_revoked",
                    &id,
                    now,
                )
                .await?;
            }
            continue;
        }
        // A device that has never sent inventory is not considered recovered.
        let Some(seen) = row.get::<Option<i64>, _>("last_seen") else {
            continue;
        };
        let offline = seen < now - 900;
        observe(
            tx,
            agent,
            tenant,
            "agent_offline",
            Some((
                offline,
                "critical",
                format!("Último contacto: {seen}"),
                seen,
            )),
            now,
        )
        .await?;
        if seen < now - 120 || seen > now {
            continue;
        }
        let Ok(inventory) = serde_json::from_str::<Inventory>(row.get("inventory")) else {
            continue;
        };
        let disk = match (inventory.disk_free_bytes, inventory.disk_total_bytes) {
            (Some(free), Some(total)) if total > 0 && free <= total => Some((
                (free as u128) * 100 < (total as u128) * 10,
                "warning",
                format!("Disco libre: {free} de {total} bytes; umbral 10%"),
                seen,
            )),
            _ => None,
        };
        observe(tx, agent, tenant, "disk_low", disk, now).await?;
        let volumes = &inventory.bitlocker_volumes;
        let failing = volumes.iter().any(|v| v.protection_status == "off");
        // Empty, unknown or error-bearing readings never establish recovery.
        let healthy = !volumes.is_empty()
            && volumes
                .iter()
                .all(|v| v.protection_status == "on" && v.errors.is_empty());
        let bitlocker = (failing || healthy).then(|| {
            (
                failing,
                "critical",
                if failing {
                    "Uno o más volúmenes reportan protección desactivada".into()
                } else {
                    "Todos los volúmenes reportados tienen protección activa".into()
                },
                seen,
            )
        });
        observe(tx, agent, tenant, "bitlocker_unprotected", bitlocker, now).await?;
    }
    Ok(())
}
