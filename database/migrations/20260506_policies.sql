CREATE TABLE IF NOT EXISTS policies (
  id                SERIAL PRIMARY KEY,
  title             TEXT NOT NULL,
  description       TEXT,
  category          VARCHAR(100) NOT NULL DEFAULT 'Бусад',
  version           INTEGER NOT NULL DEFAULT 1,
  status            VARCHAR(50) NOT NULL DEFAULT 'Draft',
  review_frequency  VARCHAR(20) NOT NULL DEFAULT 'Quarterly',
  nist_ref          VARCHAR(20),
  is_required       BOOLEAN NOT NULL DEFAULT FALSE,
  required_items    TEXT,
  organization_response TEXT,
  addressed_requirement_items TEXT,
  csf_subcategory_ids TEXT,
  last_reviewed_at  TIMESTAMP,
  next_review_at    TIMESTAMP,
  created_by        INTEGER,
  approved_by       INTEGER,
  approved_at       TIMESTAMP,
  rejection_note    TEXT,
  document_file_path TEXT,
  document_original_name TEXT,
  document_uploaded_at TIMESTAMP,
  document_note     TEXT,
  created_at        TIMESTAMP DEFAULT NOW(),
  updated_at        TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_nist_ref
  ON policies (nist_ref)
  WHERE nist_ref IS NOT NULL;
