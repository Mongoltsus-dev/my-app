-- Rename scf_controls -> nist_controls and strip the scf_ prefix from columns.
-- The table now holds NIST SP 800-53 Rev 5 controls, not SCF controls.
--
-- IMPORTANT: This migration is paired with code changes that remove the
-- auto-bootstrap of the legacy `nist_controls` table (CTL-#### custom catalog)
-- in app/api/controls/route.ts. Run the migration AND deploy the updated code
-- together — running only the migration will let the next API request
-- re-create nist_controls with the old schema and break things.
--
-- Postgres updates foreign-key references automatically when columns or tables
-- are renamed, so no constraint drop/recreate is needed.

BEGIN;

-- 1. Drop the legacy nist_controls (custom CTL-#### catalog). This frees up
--    the name for the rename below. The old table is no longer referenced
--    after the paired code change.
DROP TABLE IF EXISTS nist_controls CASCADE;

-- 2. Rename FK + cached columns on control_recommendations
ALTER TABLE control_recommendations RENAME COLUMN scf_control_id TO control_id;
ALTER TABLE control_recommendations RENAME COLUMN scf_domain     TO domain;

-- 3. Rename columns on the controls table
ALTER TABLE scf_controls RENAME COLUMN scf_control_id   TO control_id;
ALTER TABLE scf_controls RENAME COLUMN scf_domain       TO domain;
ALTER TABLE scf_controls RENAME COLUMN scf_control_name TO control_name;
ALTER TABLE scf_controls RENAME COLUMN scf_description  TO description;

-- 4. Rename the table itself
ALTER TABLE scf_controls RENAME TO nist_controls;

COMMIT;
