CREATE TABLE tenants(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE users(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('administrator','operator','approver','auditor')),
 totp_secret TEXT NOT NULL, last_totp INTEGER NOT NULL DEFAULT -1, disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), csrf TEXT NOT NULL,
 expires_at INTEGER NOT NULL, mfa_at INTEGER NOT NULL);
CREATE TABLE licenses(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), envelope TEXT NOT NULL,
 issued_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX licenses_current ON licenses(tenant_id,issued_at DESC);
CREATE TABLE activation_codes(code_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
 expires_at INTEGER NOT NULL, used_at INTEGER, agent_id TEXT);
CREATE TABLE challenges(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), agent_id TEXT NOT NULL,
 code_hash TEXT NOT NULL REFERENCES activation_codes(code_hash), public_key TEXT NOT NULL, nonce TEXT NOT NULL,
 expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE agents(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), public_key TEXT NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0, sequence INTEGER NOT NULL DEFAULT 0, inventory TEXT NOT NULL DEFAULT '{}',
 last_seen INTEGER, public_ip TEXT, version TEXT NOT NULL DEFAULT 'unknown');
CREATE TABLE commands(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), agent_id TEXT NOT NULL REFERENCES agents(id),
 requester TEXT NOT NULL REFERENCES users(id), action TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','claimed','succeeded','failed','expired','cancelled')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, approver TEXT REFERENCES users(id), approval_id TEXT,
 envelope TEXT, lease_token TEXT, claimed_at INTEGER, output TEXT, completed_at INTEGER);
CREATE INDEX commands_queue ON commands(agent_id,state,created_at);
CREATE TABLE receipts(agent_id TEXT NOT NULL REFERENCES agents(id), request_id TEXT NOT NULL, request_hash TEXT NOT NULL,
 response TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(agent_id,request_id));
CREATE TABLE rate_limits(scope TEXT PRIMARY KEY, window_start INTEGER NOT NULL, attempts INTEGER NOT NULL);
CREATE TABLE password_resets(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL,
 object_id TEXT NOT NULL, at INTEGER NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TABLE updates(channel TEXT PRIMARY KEY, envelope TEXT NOT NULL, file_path TEXT NOT NULL, filename TEXT UNIQUE NOT NULL);
