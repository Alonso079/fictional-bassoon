-- Executed with foreign_keys OFF outside the migration transaction.
CREATE TABLE users_new (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
 username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('security_observer','requester','approver','technical_operator','auditor','platform_administrator')),
 totp_secret TEXT NOT NULL, last_totp INTEGER NOT NULL DEFAULT -1, disabled INTEGER NOT NULL DEFAULT 0
);
INSERT INTO users_new SELECT id,tenant_id,username,password_hash,
 CASE role WHEN 'administrator' THEN 'platform_administrator' WHEN 'operator' THEN 'requester'
 WHEN 'approver' THEN 'approver' WHEN 'auditor' THEN 'auditor' ELSE 'security_observer' END,
 totp_secret,last_totp,disabled FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
