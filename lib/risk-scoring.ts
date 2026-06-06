// Single source of truth for the 5×5 risk-score → level banding
// (≤4 Low, ≤9 Medium, ≤16 High, else Critical).
//
// Pure module — no DB or React imports — so it is safe to import from both
// server routes (e.g. lib/residual-risk.ts) and client components
// (e.g. the risks pages' heat map).

export type RiskLevel = "Low" | "Medium" | "High" | "Critical";

export function riskLevelFromScore(score: number): RiskLevel {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}
