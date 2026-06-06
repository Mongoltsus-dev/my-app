import { pool } from "./db";
import { riskLevelFromScore } from "./risk-scoring";

// Implementation status of a recommended control → effectiveness contribution (%).
const CONTROL_STATUS_SCORE: Record<string, number> = {
  existing: 100,
  partial: 50,
  not_started: 0,
};

export async function persistResidualRisk(riskRegisterId: number): Promise<{
  inherent_score: number;
  residual_score: number;
  residual_level: string;
  control_count: number;
} | null> {
  const analysisRow = await pool.query(
    `SELECT COALESCE(inherent_risk_score, risk_score, 0) AS inherent_score
     FROM risk_analysis WHERE risk_register_id = $1`,
    [riskRegisterId],
  );
  if (analysisRow.rows.length === 0) return null;

  const inherentScore = Number(analysisRow.rows[0].inherent_score);

  const controlsResult = await pool.query(
    `SELECT risk_reduction_percent FROM control_assessments
     WHERE risk_register_id = $1 AND risk_reduction_percent > 0`,
    [riskRegisterId],
  );

  // Multiplicative reduction — each control independently reduces remaining risk
  let remaining = 1.0;
  for (const row of controlsResult.rows) {
    remaining *= 1 - Math.min(80, Number(row.risk_reduction_percent)) / 100;
  }
  // Total reduction capped at 80% (risk can never be fully eliminated)
  remaining = Math.max(0.2, remaining);

  const residualScore = Math.max(1, Math.round(inherentScore * remaining));
  const residualLevel = riskLevelFromScore(residualScore);

  await pool.query(
    `UPDATE risk_analysis
     SET residual_risk_score    = $1,
         residual_risk_level    = $2,
         residual_calculated_at = NOW(),
         updated_at             = NOW()
     WHERE risk_register_id = $3`,
    [residualScore, residualLevel, riskRegisterId],
  );

  return {
    inherent_score: inherentScore,
    residual_score: residualScore,
    residual_level: residualLevel,
    control_count: controlsResult.rows.length,
  };
}

// Control-effectiveness residual model: averages the implementation status of a
// risk's recommended controls into a control-effectiveness percentage, then
// reduces the inherent score by that percentage. This is the model used by the
// control-selection routes (previously duplicated as `recomputeCE` in both
// app/api/controls/route.ts and app/api/controls/select/route.ts).
//
// NOTE: this is a deliberately different model from persistResidualRisk above,
// which derives residual risk from per-control risk_reduction_percent in the
// detailed control-assessments flow. Both write the same residual_risk_* columns,
// so a risk that goes through both flows takes whichever value was written last.
// Unifying the two into one canonical residual figure is a risk-modeling decision
// left to the project owner; this helper only removes the duplicated copies.
export async function persistControlEffectivenessResidual(
  riskRegisterId: number,
): Promise<void> {
  const { rows } = await pool.query<{ implementation_status: string | null }>(
    `SELECT implementation_status FROM control_recommendations
     WHERE risk_register_id = $1`,
    [riskRegisterId],
  );
  if (rows.length === 0) return;

  const controlEffectiveness = Math.round(
    rows.reduce(
      (sum, row) =>
        sum + (CONTROL_STATUS_SCORE[row.implementation_status ?? "not_started"] ?? 0),
      0,
    ) / rows.length,
  );

  const analysisRow = await pool.query<{ inherent: number | null }>(
    `SELECT inherent_risk_score AS inherent FROM risk_analysis
     WHERE risk_register_id = $1`,
    [riskRegisterId],
  );
  const inherentRaw = analysisRow.rows[0]?.inherent;
  // Preserve prior behavior: with no inherent score, residual stays unscored (NULL).
  const inherent = inherentRaw == null ? null : Number(inherentRaw);
  const residualScore =
    inherent == null
      ? null
      : Math.round(inherent * (1 - controlEffectiveness / 100));
  const residualLevel =
    residualScore == null ? null : riskLevelFromScore(residualScore);

  await pool.query(
    `UPDATE risk_analysis
        SET control_effectiveness  = $1,
            residual_risk_score    = $2,
            residual_risk_level    = $3,
            residual_calculated_at = NOW(),
            updated_at             = NOW()
      WHERE risk_register_id = $4`,
    [controlEffectiveness, residualScore, residualLevel, riskRegisterId],
  );
}
