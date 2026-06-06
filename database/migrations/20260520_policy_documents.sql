ALTER TABLE policies
  ADD COLUMN IF NOT EXISTS document_file_path TEXT,
  ADD COLUMN IF NOT EXISTS document_original_name TEXT,
  ADD COLUMN IF NOT EXISTS document_uploaded_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS document_note TEXT;
