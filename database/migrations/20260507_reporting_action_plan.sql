CREATE TABLE IF NOT EXISTS risk_metric_snapshots (
  id SERIAL PRIMARY KEY,
  snapshot_date DATE UNIQUE NOT NULL DEFAULT CURRENT_DATE,
  avg_risk_score NUMERIC(5,2) DEFAULT 0,
  total_risks INTEGER DEFAULT 0,
  critical_risks INTEGER DEFAULT 0,
  high_risks INTEGER DEFAULT 0,
  medium_risks INTEGER DEFAULT 0,
  low_risks INTEGER DEFAULT 0,
  open_vulnerabilities INTEGER DEFAULT 0,
  implemented_controls INTEGER DEFAULT 0,
  total_controls INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS action_plan_items (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  mapped_subcategory VARCHAR(50),
  priority VARCHAR(20) DEFAULT 'Medium',
  risk_reduction_value INTEGER DEFAULT 3 CHECK (risk_reduction_value BETWEEN 1 AND 5),
  owner VARCHAR(255),
  due_date DATE,
  status VARCHAR(50) DEFAULT 'Not Started',
  notes TEXT,
  source_type VARCHAR(50),
  source_id INTEGER,
  risk_register_id INTEGER,
  control_recommendation_id INTEGER,
  asset_id INTEGER,
  generated_from VARCHAR(100),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS source_type VARCHAR(50);
ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS source_id INTEGER;
ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS risk_register_id INTEGER;
ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS control_recommendation_id INTEGER;
ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS asset_id INTEGER;
ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS generated_from VARCHAR(100);

CREATE UNIQUE INDEX IF NOT EXISTS idx_action_plan_control_recommendation
  ON action_plan_items(control_recommendation_id)
  WHERE control_recommendation_id IS NOT NULL;