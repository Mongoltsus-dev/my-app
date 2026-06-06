/**
 * NIST CSF 2.0 Control Objective Mapping
 *
 * Maps each NIST CSF 2.0 category to a recommended NIST control objective
 * with an actionable implementation description for SMEs.
 */

export interface NISTControl {
  controlId: string;
  controlName: string;
  description: string;
  nistFunction: string;
}

export const NIST_CONTROL_MAPPING: Record<string, NISTControl> = {
  // ===================== GOVERN (GV) =====================
  "GV.OC": {
    controlId: "GV.OC",
    controlName: "Organizational Context & Governance",
    description:
      "Establish and maintain documentation of the organization's mission, stakeholders, legal obligations, and risk appetite to guide cybersecurity strategy decisions.",
    nistFunction: "Govern",
  },
  "GV.RM": {
    controlId: "GV.RM",
    controlName: "Risk Management Strategy",
    description:
      "Develop and implement an enterprise-wide risk management strategy that defines risk tolerance levels, assessment methodologies, and risk treatment options.",
    nistFunction: "Govern",
  },
  "GV.RR": {
    controlId: "GV.RR",
    controlName: "Roles, Responsibilities & Authorities",
    description:
      "Define and communicate cybersecurity roles, responsibilities, and authorities across leadership, IT, and business units with clear escalation paths.",
    nistFunction: "Govern",
  },
  "GV.PO": {
    controlId: "GV.PO",
    controlName: "Cybersecurity Policy",
    description:
      "Create, approve, and distribute cybersecurity policies that are reviewed annually and aligned with the organization's risk management strategy.",
    nistFunction: "Govern",
  },
  "GV.OV": {
    controlId: "GV.OV",
    controlName: "Governance Oversight",
    description:
      "Ensure senior leadership receives regular reports on cybersecurity risk posture, control effectiveness, and resource adequacy for informed decision-making.",
    nistFunction: "Govern",
  },
  "GV.SC": {
    controlId: "GV.SC",
    controlName: "Supply Chain Risk Management",
    description:
      "Establish third-party risk management processes including vendor assessments, contractual security requirements, and ongoing monitoring of supplier risk.",
    nistFunction: "Govern",
  },

  // ===================== IDENTIFY (ID) =====================
  "ID.AM": {
    controlId: "ID.AM",
    controlName: "Asset Inventory & Management",
    description:
      "Maintain a comprehensive, up-to-date inventory of all IT assets (hardware, software, data, systems) with ownership, criticality, and classification tagging.",
    nistFunction: "Identify",
  },
  "ID.RA": {
    controlId: "ID.RA",
    controlName: "Risk Assessment Process",
    description:
      "Conduct periodic risk assessments to identify threats and vulnerabilities for each asset, evaluate impact and likelihood, and prioritize treatment actions.",
    nistFunction: "Identify",
  },
  "ID.IM": {
    controlId: "ID.IM",
    controlName: "Continuous Improvement",
    description:
      "Track cybersecurity improvement actions driven by lessons learned, audit findings, and maturity assessments to continuously strengthen the security posture.",
    nistFunction: "Identify",
  },

  // ===================== PROTECT (PR) =====================
  "PR.AA": {
    controlId: "PR.AA",
    controlName: "Identity & Access Management",
    description:
      "Implement identity lifecycle management, multi-factor authentication, role-based access controls, and least-privilege access enforcement across all systems.",
    nistFunction: "Protect",
  },
  "PR.AT": {
    controlId: "PR.AT",
    controlName: "Security Awareness & Training",
    description:
      "Deliver role-based cybersecurity awareness training including phishing simulations, secure coding practices, and incident reporting procedures.",
    nistFunction: "Protect",
  },
  "PR.DS": {
    controlId: "PR.DS",
    controlName: "Data Security & Encryption",
    description:
      "Classify data, encrypt sensitive data at rest and in transit, implement DLP controls, and manage cryptographic keys according to established policy.",
    nistFunction: "Protect",
  },
  "PR.PS": {
    controlId: "PR.PS",
    controlName: "Platform Security & Hardening",
    description:
      "Establish and enforce secure configuration baselines for all platforms, apply patches promptly, and disable unnecessary services and default credentials.",
    nistFunction: "Protect",
  },
  "PR.IR": {
    controlId: "PR.IR",
    controlName: "Infrastructure Resilience",
    description:
      "Design infrastructure with redundancy, failover mechanisms, and capacity planning. Test backup and disaster recovery procedures regularly.",
    nistFunction: "Protect",
  },

  // ===================== DETECT (DE) =====================
  "DE.CM": {
    controlId: "DE.CM",
    controlName: "Continuous Security Monitoring",
    description:
      "Deploy SIEM, EDR, and network monitoring tools to continuously collect, correlate, and analyze security events across all critical systems.",
    nistFunction: "Detect",
  },
  "DE.AE": {
    controlId: "DE.AE",
    controlName: "Adverse Event Analysis",
    description:
      "Establish processes and tools for analyzing anomalous activities, triaging alerts, and determining whether events constitute actual security incidents.",
    nistFunction: "Detect",
  },

  // ===================== RESPOND (RS) =====================
  "RS.MA": {
    controlId: "RS.MA",
    controlName: "Incident Management",
    description:
      "Establish a formal incident response plan with defined severity levels, escalation procedures, roles, and playbooks for common attack scenarios.",
    nistFunction: "Respond",
  },
  "RS.AN": {
    controlId: "RS.AN",
    controlName: "Incident Analysis & Forensics",
    description:
      "Perform thorough incident analysis including forensic evidence collection, root cause determination, scope assessment, and timeline reconstruction.",
    nistFunction: "Respond",
  },
  "RS.CO": {
    controlId: "RS.CO",
    controlName: "Incident Reporting & Communication",
    description:
      "Define communication procedures for notifying internal leadership, affected parties, regulators, and law enforcement during and after security incidents.",
    nistFunction: "Respond",
  },
  "RS.MI": {
    controlId: "RS.MI",
    controlName: "Incident Containment & Mitigation",
    description:
      "Implement procedures to contain active threats, eradicate malicious artifacts, and mitigate the impact of incidents on business operations.",
    nistFunction: "Respond",
  },

  // ===================== RECOVER (RC) =====================
  "RC.RP": {
    controlId: "RC.RP",
    controlName: "Recovery Plan Execution",
    description:
      "Maintain and test disaster recovery and business continuity plans that restore critical systems and data within defined RTO/RPO targets.",
    nistFunction: "Recover",
  },
  "RC.CO": {
    controlId: "RC.CO",
    controlName: "Recovery Communication",
    description:
      "Establish communication plans for recovery activities, including status updates to stakeholders, customers, and regulators during restoration efforts.",
    nistFunction: "Recover",
  },
};

/**
 * All NIST CSF 2.0 functions in order
 */
export const NIST_CSF_FUNCTIONS = [
  "Govern",
  "Identify",
  "Protect",
  "Detect",
  "Respond",
  "Recover",
] as const;

/**
 * Color mapping for each NIST CSF 2.0 function
 */
export const FUNCTION_COLORS: Record<
  string,
  { bg: string; text: string; border: string; dot: string }
> = {
  Govern: {
    bg: "bg-pink-500/10",
    text: "text-pink-600",
    border: "border-pink-500/20",
    dot: "bg-pink-500",
  },
  Identify: {
    bg: "bg-blue-500/10",
    text: "text-blue-600",
    border: "border-blue-500/20",
    dot: "bg-blue-500",
  },
  Protect: {
    bg: "bg-violet-500/10",
    text: "text-violet-600",
    border: "border-violet-500/20",
    dot: "bg-violet-500",
  },
  Detect: {
    bg: "bg-cyan-500/10",
    text: "text-cyan-600",
    border: "border-cyan-500/20",
    dot: "bg-cyan-500",
  },
  Respond: {
    bg: "bg-orange-500/10",
    text: "text-orange-600",
    border: "border-orange-500/20",
    dot: "bg-orange-500",
  },
  Recover: {
    bg: "bg-emerald-500/10",
    text: "text-emerald-600",
    border: "border-emerald-500/20",
    dot: "bg-emerald-500",
  },
};

/**
 * Get the recommended NIST control objective based on a NIST CSF 2.0 category code.
 */
export function getRecommendedNISTControl(
  category: string | null,
): NISTControl {
  const fallback: NISTControl = {
    controlId: "ID.RA",
    controlName: "General NIST CSF Control Objective",
    description:
      "Implement baseline NIST CSF risk assessment and treatment activities appropriate to the identified risk.",
    nistFunction: "General",
  };

  if (!category) return fallback;

  // Handle subcategory codes like "PR.AA-01" → extract "PR.AA"
  const baseCategory = category.includes("-")
    ? category.substring(0, category.lastIndexOf("-"))
    : category;

  return (
    NIST_CONTROL_MAPPING[baseCategory] ||
    NIST_CONTROL_MAPPING[category] ||
    fallback
  );
}
