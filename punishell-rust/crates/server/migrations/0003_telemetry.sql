CREATE TABLE telemetry_samples(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 agent_id TEXT NOT NULL REFERENCES agents(id),
 captured_at INTEGER NOT NULL,
 version TEXT NOT NULL,
 uptime_millis INTEGER NOT NULL,
 disk_total_bytes INTEGER,
 disk_free_bytes INTEGER,
 ram_installed_bytes INTEGER,
 ram_usable_bytes INTEGER,
 adapter_count INTEGER NOT NULL,
 wifi_count INTEGER NOT NULL,
 interactive_user_count INTEGER NOT NULL,
 error_count INTEGER NOT NULL
);
CREATE INDEX telemetry_agent_time ON telemetry_samples(agent_id,captured_at DESC);
CREATE INDEX telemetry_tenant_time ON telemetry_samples(tenant_id,captured_at DESC);

