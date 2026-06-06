import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  HeadingLevel,
  LevelFormat,
  PageNumber,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from "docx";
import fs from "fs";
import path from "path";

const __dirname = path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Z]:)/, "$1");

// ── helpers ──────────────────────────────────────────────────────────────────

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 120 },
    children: [new TextRun({ text, bold: true, size: 36, font: "Arial" })],
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 100 },
    children: [new TextRun({ text, bold: true, size: 28, font: "Arial", color: "1F497D" })],
  });
}

function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 200, after: 80 },
    children: [new TextRun({ text, bold: true, size: 24, font: "Arial", color: "2E75B6" })],
  });
}

function para(text, opts = {}) {
  return new Paragraph({
    spacing: { before: 60, after: 80 },
    children: [new TextRun({ text, font: "Arial", size: 22, ...opts })],
  });
}

function bullet(text) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, font: "Arial", size: 22 })],
  });
}

function numbered(text) {
  return new Paragraph({
    numbering: { reference: "numbers", level: 0 },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, font: "Arial", size: 22 })],
  });
}

function spacer() {
  return new Paragraph({ spacing: { before: 60, after: 60 }, children: [] });
}

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };

function headerRow(cells, colWidths) {
  return new TableRow({
    tableHeader: true,
    children: cells.map((text, i) =>
      new TableCell({
        borders,
        width: { size: colWidths[i], type: WidthType.DXA },
        shading: { fill: "2E75B6", type: ShadingType.CLEAR },
        margins: { top: 100, bottom: 100, left: 140, right: 140 },
        children: [
          new Paragraph({
            children: [new TextRun({ text, bold: true, color: "FFFFFF", font: "Arial", size: 20 })],
          }),
        ],
      }),
    ),
  });
}

function dataRow(cells, colWidths, shade = false) {
  return new TableRow({
    children: cells.map((text, i) =>
      new TableCell({
        borders,
        width: { size: colWidths[i], type: WidthType.DXA },
        shading: { fill: shade ? "F2F7FC" : "FFFFFF", type: ShadingType.CLEAR },
        margins: { top: 80, bottom: 80, left: 140, right: 140 },
        children: [
          new Paragraph({
            children: [new TextRun({ text: text ?? "", font: "Arial", size: 20 })],
          }),
        ],
      }),
    ),
  });
}

function table(headerCells, rows, colWidths) {
  const total = colWidths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: [
      headerRow(headerCells, colWidths),
      ...rows.map((row, idx) => dataRow(row, colWidths, idx % 2 === 0)),
    ],
  });
}

// ── content ──────────────────────────────────────────────────────────────────

const doc = new Document({
  numbering: {
    config: [
      {
        reference: "bullets",
        levels: [{
          level: 0, format: LevelFormat.BULLET, text: "•",
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
      {
        reference: "numbers",
        levels: [{
          level: 0, format: LevelFormat.DECIMAL, text: "%1.",
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
    ],
  },
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
      },
    },
    footers: {
      default: new Footer({
        children: [
          new Paragraph({
            alignment: AlignmentType.RIGHT,
            children: [
              new TextRun({ text: "CyberGuardX Documentation  |  Page ", font: "Arial", size: 18, color: "888888" }),
              new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 18, color: "888888" }),
            ],
          }),
        ],
      }),
    },
    children: [
      // ── Title page ──
      spacer(), spacer(),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 600, after: 200 },
        children: [new TextRun({ text: "CyberGuardX", bold: true, size: 64, font: "Arial", color: "2E75B6" })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 0, after: 200 },
        children: [new TextRun({ text: "International Risk Assessment System", size: 36, font: "Arial", color: "444444" })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 0, after: 80 },
        children: [new TextRun({ text: "Documentation & Improvement Guide", size: 28, font: "Arial", color: "666666" })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 200, after: 0 },
        children: [new TextRun({ text: "NIST CSF 2.0 Aligned", size: 22, font: "Arial", color: "888888", italics: true })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 80, after: 0 },
        children: [new TextRun({ text: "May 2026", size: 22, font: "Arial", color: "888888" })],
      }),
      spacer(), spacer(), spacer(),
      new Paragraph({ pageBreakBefore: true, children: [] }),

      // ── Section 1 ──
      h1("1. Current Page Inventory"),
      para("The application has 11 pages covering the full NIST CSF 2.0 risk assessment workflow:"),
      spacer(),
      table(
        ["Route", "Mongolian Label", "Purpose"],
        [
          ["/", "Хянах самбар", "Dashboard — CSF radar chart, tier rings, KPI cards, gap table"],
          ["/profile", "Профайл", "Organization context — name, industry, risk appetite"],
          ["/assets", "Хөрөнгө", "IT asset registry with security posture flags"],
          ["/threats", "Аюул занал", "Threat catalog + asset-threat mapping"],
          ["/vulnerabilities", "Эмзэг байдал", "CVE tracking, CISA KEV import, remediation workflow"],
          ["/assessments", "Эрсдэл", "Core risk register — inherent/residual scoring, 5x5 matrix"],
          ["/controls", "NIST-ийн хяналтууд", "106+ NIST CSF 2.0 subcategories grouped by function"],
          ["/control-assessments", "Хяналтын үнэлгээ", "Control effectiveness — maturity, evidence, risk reduction %"],
          ["/gap-analysis", "Арга хэмжээний төлөвлөгөө", "Remediation tracking — owner, due date, status"],
          ["/reports", "Тайлан", "Export hub — CSV/Excel for 4 report types"],
          ["/reports/risk-treatment", "Эрсдэлийн арга хэмжээ", "Live treatment dashboard — Mitigate/Accept/Transfer/Avoid"],
        ],
        [1600, 2400, 5360],
      ),

      spacer(),
      new Paragraph({ pageBreakBefore: true, children: [] }),

      // ── Section 2 ──
      h1("2. Risk Assessment Workflow"),
      para("The application implements an end-to-end NIST CSF 2.0 aligned workflow:"),
      spacer(),
      numbered("Profile → Assets → Threats → Vulnerabilities  (data collection phase)"),
      numbered("Assessments — inherent likelihood x impact scoring (5x5 matrix = score 1-25)"),
      numbered("Controls / Control Assessments — maps NIST CSF 2.0 subcategories to risks"),
      numbered("Residual risk recalculated after control implementation effectiveness is scored"),
      numbered("Risk treatment decision: Mitigate / Accept / Transfer / Avoid"),
      numbered("Action Plan — auto-synced from control recommendations with owner and due date"),
      numbered("Reports — CSV/Excel export and live risk treatment dashboard"),

      spacer(),
      new Paragraph({ pageBreakBefore: true, children: [] }),

      // ── Section 3 ──
      h1("3. NIST CSF 2.0 Function Coverage"),
      spacer(),
      table(
        ["Function", "Color", "Pages Covering It", "Current Gap"],
        [
          ["Govern (GV)", "Pink", "/profile only", "No policy tracking, no supply chain, no governance docs"],
          ["Identify (ID)", "Blue", "/assets, /threats", "No business impact analysis, no dependency mapping"],
          ["Protect (PR)", "Violet", "/controls, /control-assessments", "No access control workflow, no training records"],
          ["Detect (DE)", "Cyan", "/vulnerabilities", "No automated monitoring, detection is manual only"],
          ["Respond (RS)", "Orange", "/gap-analysis", "No incident log, no response playbooks"],
          ["Recover (RC)", "Emerald", "/reports", "No recovery plans, no lessons-learned records"],
        ],
        [1600, 1200, 2400, 4160],
      ),

      spacer(),
      new Paragraph({ pageBreakBefore: true, children: [] }),

      // ── Section 4 ──
      h1("4. Detailed Improvement Areas"),

      h2("4.1  Govern (GV) — The Biggest Gap"),
      para("The /profile page only stores basic org info (name, industry, risk appetite). NIST CSF 2.0 introduced GV as a brand-new function specifically because governance was under-represented in CSF 1.1. It requires 6 subcategories:"),
      spacer(),
      table(
        ["Subcategory", "What It Requires"],
        [
          ["GV.OC", "Document mission, stakeholders, legal/regulatory obligations"],
          ["GV.RM", "Formal risk appetite statement linked to scoring thresholds"],
          ["GV.RR", "Defined roles — who is accountable for each risk decision"],
          ["GV.PO", "Policies with review cycles and approval status"],
          ["GV.OV", "Board/executive oversight records"],
          ["GV.SC", "Third-party/supply chain risk criteria"],
        ],
        [1800, 7560],
      ),
      spacer(),
      para("Recommended pages to build:", { bold: true }),
      bullet("/policies — Policy registry: title, GV subcategory, owner, review date, approval status (Draft > Under Review > Approved), document URL"),
      bullet("/governance — Risk appetite statement formally linked to 1-25 score thresholds, oversight meeting log, board review dates"),
      spacer(),
      para("Database tables needed:", { bold: true }),
      bullet("governance_documents (id, title, description, gv_subcategory, owner, review_date, approval_status, document_url)"),
      bullet("risk_appetite_statement (id, threshold_low, threshold_medium, threshold_high, threshold_critical, approved_by, approved_date)"),

      spacer(),
      h2("4.2  Assessments Page — Risk Register Needs Strengthening"),
      para("The /assessments page does inherent/residual scoring with a 5x5 matrix. This is correct but several important fields are missing:"),
      spacer(),
      table(
        ["Missing Field", "Why It Matters"],
        [
          ["Risk owner (separate from asset owner)", "NIST GV.RR requires accountability assignment per risk"],
          ["Treatment rationale", "Accept decisions need documented justification for audits"],
          ["Risk review date", "Risks should expire and require re-assessment periodically"],
          ["Linked regulatory requirement", "Maps each risk to compliance obligations (ISO 27001, SOC2, GDPR)"],
          ["Residual risk sign-off", "Who approved accepting the residual risk level"],
        ],
        [3600, 5760],
      ),
      spacer(),
      para("Scoring note: Current 5x5 uses thresholds: <=4 Low, <=9 Medium, <=16 High, >=17 Critical. The inherent vs. residual gap (how much controls actually reduced risk) is not visualized. Recommend adding a Risk Reduction % column to the register table."),

      spacer(),
      h2("4.3  Vulnerabilities Page — Detection Is Manual Only"),
      para("CVE tracking, CISA KEV import, severity/CVSS scoring, and remediation status are solid for DE.CM-01. However detection only works when someone manually clicks Scan or imports."),
      spacer(),
      para("What to add:", { bold: true }),
      bullet("Scheduled CISA KEV sync — background job every 24 hours checking CISA KEV feed for new CVEs matching software/services in the asset registry, auto-creating vulnerability records"),
      bullet("Vulnerability aging — flag vulnerabilities open longer than SLA: Critical = 15 days, High = 30 days, Medium = 60 days, Low = 90 days"),
      bullet("Mean Time to Remediate (MTTR) — calculate average days from discovered_date to remediated_date per severity level"),
      spacer(),
      para("New stat cards recommended for /vulnerabilities:", { bold: true }),
      bullet("Open Critical (SLA: 15d)  |  Overdue SLAs  |  MTTR (Critical)  |  MTTR (High)"),

      spacer(),
      h2("4.4  Controls & Control Assessments — Evidence Is Hollow"),
      para("The /control-assessments page has fields for implementation_status, effectiveness_rating (1-5), maturity_level (1-4), and a text evidence field. The problem is evidence is just free text with no timestamping, versioning, or audit trail."),
      spacer(),
      para("What to add:", { bold: true }),
      bullet("Evidence attachments table — assessment_evidence (id, control_assessment_id, assessor, submitted_at, evidence_text, evidence_type) so each submission is timestamped with who submitted it"),
      bullet("Assessment schedule — each control should have a next_review_date; overdue reviews surface as warning badges"),
      bullet("Maturity trend — store historical maturity scores to show progression (e.g. GV.PO went from Maturity 1 to 3 over 6 months)"),

      spacer(),
      h2("4.5  Action Plan — Missing Link to Governance"),
      para("The /gap-analysis auto-syncs from control recommendations and allows status/owner/due date management. This is solid. What is missing:"),
      bullet("Risk treatment sign-off workflow — Accept decisions should require a named approver and approval date, appearing in the action plan as Accepted by CISO on [date]"),
      bullet("Action plan to CSF gap linkage — when an action item is Done, the corresponding CSF gap tier should auto-update on the dashboard"),
      bullet("SLA breach alerting — action items past due_date should surface as alerts on the dashboard"),

      spacer(),
      h2("4.6  Reports — Missing Executive View"),
      spacer(),
      table(
        ["Report", "What It Should Show"],
        [
          ["Executive Summary", "One-page: overall risk posture score, top 5 risks, CSF tier by function, open critical actions"],
          ["Compliance Gap Report", "Per NIST subcategory: current tier, target tier, gap, responsible owner, action plan status"],
          ["Risk Trend Report", "Month-over-month: avg risk score, critical/high count, controls implemented, vulnerabilities remediated"],
          ["Audit Evidence Package", "Exportable bundle of: control assessment evidence + risk register + treatment decisions"],
        ],
        [2800, 6560],
      ),
      spacer(),
      para("Note: The /api/reports/risk-trends endpoint already stores daily metric snapshots in risk_metric_snapshots. A frontend page at /reports/trends is needed to visualize this data as a line chart."),

      spacer(),
      h2("4.7  Dashboard — Gap Table Needs Automation"),
      para("The dashboard shows a gap table where target_tier is set manually per subcategory. The current_tier is derived from only 4 asset posture flags (MFA, encryption, logging, backup coverage %)."),
      spacer(),
      para("Problems:", { bold: true }),
      bullet("Current tier computed from only 4 binary flags — too coarse for 106 subcategories"),
      bullet("Target tiers set manually with no link to the organization's risk appetite statement"),
      bullet("Gaps do not automatically close when action plan items are completed"),
      spacer(),
      para("Recommended improvements:", { bold: true }),
      numbered("Auto-close gaps: when an action plan item mapped to subcategory X is marked Done, increment current_tier for that subcategory by 1 (up to target)"),
      numbered("Risk appetite to tier target mapping: if risk appetite is Low, auto-set target tiers to 3 (Repeatable); if High, target tier 2 is acceptable"),
      numbered("Coverage score per function: show a % completion ring per GV/ID/PR/DE/RS/RC function based on (subcategories at target / total subcategories)"),

      spacer(),
      new Paragraph({ pageBreakBefore: true, children: [] }),

      // ── Section 5 ──
      h1("5. Recommended Build Order"),
      spacer(),
      table(
        ["Priority", "Page / Feature", "NIST Coverage", "Effort"],
        [
          ["1", "/policies — Policy registry with GV subcategory mapping", "GV.PO, GV.OV", "Low"],
          ["2", "Risk register: add owner, review date, treatment sign-off", "GV.RR, GV.RM", "Medium"],
          ["3", "Vulnerability SLA aging + MTTR metrics", "DE.CM", "Low"],
          ["4", "Control assessment evidence timestamps", "PR, ID", "Medium"],
          ["5", "/reports/trends — risk trend line chart (data already exists)", "All", "Low"],
          ["6", "Auto-close CSF gaps when action items complete", "All", "Medium"],
          ["7", "/incidents — Incident log + response actions", "RS, RC", "Medium"],
          ["8", "Scheduled CISA KEV sync (background job)", "DE.CM", "High"],
          ["9", "Executive summary report page", "All", "Medium"],
          ["10", "Risk appetite statement linked to score thresholds", "GV.RM", "Low"],
        ],
        [800, 4800, 1800, 1960],
      ),

      spacer(),
      new Paragraph({ pageBreakBefore: true, children: [] }),

      // ── Section 6 ──
      h1("6. Quick Wins — Minimal Code Changes Required"),
      spacer(),
      para("These four improvements can be done immediately with minimal effort:"),
      spacer(),
      numbered("Risk register review date — add a review_date column to risk_register and show a badge on /assessments for risks not reviewed in 90+ days"),
      numbered("Vulnerability MTTR — add a computed stat to /vulnerabilities showing AVG(remediated_date - discovered_date) per severity level"),
      numbered("Trends page — risk_metric_snapshots is already populated daily; add a /reports/trends page with a Recharts line chart reading from /api/reports/risk-trends"),
      numbered("Action plan overdue badge — on /gap-analysis, highlight rows where due_date is before today and status is not Done or Accepted"),

      spacer(), spacer(),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 400, after: 0 },
        children: [new TextRun({ text: "— End of Document —", font: "Arial", size: 20, color: "888888", italics: true })],
      }),
    ],
  }],
});

const outPath = path.join(__dirname, "..", "public", "CyberGuardX_Risk_Assessment_Documentation.docx");
Packer.toBuffer(doc).then((buffer) => {
  fs.writeFileSync(outPath, buffer);
  console.log("Created:", outPath);
});
