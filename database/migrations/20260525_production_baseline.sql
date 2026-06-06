CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  full_name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role_id INTEGER NOT NULL DEFAULT 2,
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique_idx ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS asset_types (
  id SERIAL PRIMARY KEY,
  type_name VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
  id SERIAL PRIMARY KEY,
  asset_type_id INTEGER,
  asset_type VARCHAR(100),
  owner_id INTEGER,
  asset_name VARCHAR(255) NOT NULL,
  asset_code VARCHAR(50) UNIQUE,
  business_owner VARCHAR(255),
  technical_owner VARCHAR(255),
  department VARCHAR(255),
  data_classification VARCHAR(50),
  access_level VARCHAR(50),
  authentication_method VARCHAR(50),
  supports_critical_service BOOLEAN DEFAULT FALSE,
  hosting VARCHAR(100),
  rto_hours NUMERIC(10,2),
  rpo_hours NUMERIC(10,2),
  criticality VARCHAR(100) NOT NULL DEFAULT 'Medium',
  internet_exposed BOOLEAN DEFAULT FALSE,
  backup_enabled BOOLEAN DEFAULT FALSE,
  encryption_enabled BOOLEAN DEFAULT FALSE,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  logging_enabled BOOLEAN DEFAULT FALSE,
  edr_enabled BOOLEAN DEFAULT FALSE,
  vuln_scanning_enabled BOOLEAN DEFAULT FALSE,
  country VARCHAR(100),
  region VARCHAR(100),
  key_users_customers VARCHAR(500),
  cmdb_ci_id VARCHAR(100),
  notes TEXT,
  status VARCHAR(50) DEFAULT 'Active',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threats (
  id SERIAL PRIMARY KEY,
  threat_name VARCHAR(255) NOT NULL,
  description TEXT,
  threat_type VARCHAR(100),
  likelihood_level INTEGER DEFAULT 3,
  potential_impact VARCHAR(50),
  nist_category VARCHAR(100),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id SERIAL PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  threat_id INTEGER REFERENCES threats(id) ON DELETE SET NULL,
  cve_id VARCHAR(100),
  title VARCHAR(255) NOT NULL DEFAULT 'Untitled vulnerability',
  description TEXT,
  vulnerability_type VARCHAR(100),
  severity VARCHAR(50) NOT NULL DEFAULT 'Medium',
  cvss_score NUMERIC(3,1),
  status VARCHAR(50) DEFAULT 'open',
  discovered_at TIMESTAMPTZ DEFAULT NOW(),
  remediated_at TIMESTAMPTZ,
  remediation_notes TEXT,
  reference_url TEXT,
  source VARCHAR(100) DEFAULT 'manual',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_threat_id ON vulnerabilities(threat_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset_threat ON vulnerabilities(asset_id, threat_id);

ALTER TABLE csf_subcategories ADD COLUMN IF NOT EXISTS title TEXT;
