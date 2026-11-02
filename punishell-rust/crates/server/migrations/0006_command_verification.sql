ALTER TABLE commands ADD COLUMN verification_state TEXT CHECK(verification_state IN ('pending','verified','not_verified','inconclusive'));
ALTER TABLE commands ADD COLUMN verification_sequence INTEGER;
ALTER TABLE commands ADD COLUMN verification_deadline INTEGER;
ALTER TABLE commands ADD COLUMN verification_at INTEGER;
ALTER TABLE commands ADD COLUMN verification_detail TEXT;
ALTER TABLE commands ADD COLUMN verification_last_status TEXT;
CREATE INDEX commands_verification ON commands(agent_id,verification_state);
