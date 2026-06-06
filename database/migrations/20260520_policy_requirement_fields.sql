ALTER TABLE policies
  ADD COLUMN IF NOT EXISTS required_items TEXT,
  ADD COLUMN IF NOT EXISTS organization_response TEXT,
  ADD COLUMN IF NOT EXISTS csf_subcategory_ids TEXT;
