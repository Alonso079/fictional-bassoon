ALTER TABLE telemetry_samples ADD COLUMN bitlocker_protected_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_samples ADD COLUMN bitlocker_unprotected_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_samples ADD COLUMN bitlocker_unknown_count INTEGER NOT NULL DEFAULT 0;

