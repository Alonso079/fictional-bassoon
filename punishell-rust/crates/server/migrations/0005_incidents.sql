CREATE TABLE incidents(
 id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 agent_id TEXT NOT NULL REFERENCES agents(id),
 kind TEXT NOT NULL CHECK(kind IN ('agent_offline','disk_low','bitlocker_unprotected')),
 severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
 state TEXT NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
 first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL,
 evidence_at INTEGER NOT NULL,
 detail TEXT NOT NULL,
 acknowledged_by TEXT REFERENCES users(id),
 acknowledged_at INTEGER,
 resolved_at INTEGER
);
CREATE UNIQUE INDEX incidents_active ON incidents(agent_id,kind) WHERE state IN ('open','acknowledged');
CREATE INDEX incidents_tenant_time ON incidents(tenant_id,first_seen DESC);
