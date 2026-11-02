//! Post-execution evidence is separate from the agent's execution result.
use crate::store::{audit, Result};
use punishell_protocol::{wire::Inventory, Action};
use sqlx::{Row, Sqlite, Transaction};

pub async fn start(
    tx: &mut Transaction<'_, Sqlite>,
    command: &str,
    sequence: i64,
    now: i64,
) -> Result<()> {
    sqlx::query("UPDATE commands SET verification_state='pending',verification_sequence=?,verification_deadline=?,verification_detail='Esperando inventario posterior del volumen solicitado' WHERE id=?")
        .bind(sequence).bind(now + 900).bind(command).execute(&mut **tx).await?;
    Ok(())
}

pub async fn observe(
    tx: &mut Transaction<'_, Sqlite>,
    agent: &str,
    inventory: &Inventory,
    sequence: i64,
    now: i64,
) -> Result<()> {
    let commands = sqlx::query("SELECT id,tenant_id,action FROM commands WHERE agent_id=? AND verification_state='pending' AND verification_sequence<? AND verification_deadline>?")
        .bind(agent).bind(sequence).bind(now).fetch_all(&mut **tx).await?;
    for command in commands {
        let Action::ResumeBitLockerProtection { mount_point } =
            serde_json::from_str(command.get("action"))?
        else {
            continue;
        };
        let volumes: Vec<_> = inventory
            .bitlocker_volumes
            .iter()
            .filter(|v| v.mount_point.as_deref() == Some(&mount_point))
            .collect();
        // Missing, duplicate and error-bearing volume readings are inconclusive.
        let status = if volumes.len() == 1 && volumes[0].errors.is_empty() {
            match volumes[0].protection_status.as_str() {
                "on" => "on",
                "off" => "off",
                _ => "unknown",
            }
        } else {
            "unknown"
        };
        let verified = status == "on";
        let id: &str = command.get("id");
        let detail =
            format!("Unidad {mount_point}: protección {status}; evidencia en secuencia {sequence}");
        sqlx::query("UPDATE commands SET verification_state=?,verification_at=?,verification_last_status=?,verification_detail=? WHERE id=?")
            .bind(if verified { "verified" } else { "pending" }).bind(now).bind(status).bind(detail).bind(id)
            .execute(&mut **tx).await?;
        if verified {
            audit(
                tx,
                command.get("tenant_id"),
                agent,
                "command_verified",
                id,
                now,
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn expire(tx: &mut Transaction<'_, Sqlite>, now: i64) -> Result<()> {
    let commands = sqlx::query("SELECT c.id,c.tenant_id,c.verification_last_status,a.revoked FROM commands c JOIN agents a ON a.id=c.agent_id WHERE c.verification_state='pending' AND (c.verification_deadline<=? OR a.revoked=1)")
        .bind(now).fetch_all(&mut **tx).await?;
    for command in commands {
        let revoked: bool = command.get("revoked");
        let status = if !revoked
            && command
                .get::<Option<String>, _>("verification_last_status")
                .as_deref()
                == Some("off")
        {
            "not_verified"
        } else {
            "inconclusive"
        };
        let detail = if revoked {
            "Equipo revocado antes de confirmar la protección"
        } else if status == "not_verified" {
            "Plazo agotado; la última lectura válida reportó protección desactivada"
        } else {
            "Plazo agotado sin evidencia suficiente de protección"
        };
        let id: &str = command.get("id");
        sqlx::query("UPDATE commands SET verification_state=?,verification_detail=? WHERE id=?")
            .bind(status)
            .bind(detail)
            .bind(id)
            .execute(&mut **tx)
            .await?;
        audit(
            tx,
            command.get("tenant_id"),
            "verification-engine",
            "command_verification_closed",
            id,
            now,
        )
        .await?;
    }
    Ok(())
}
