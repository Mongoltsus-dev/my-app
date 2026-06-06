export type CsfScopeStatus = "in_scope" | "out_of_scope" | "undecided";

export type CsfFunctionCode = "GV" | "ID" | "PR" | "DE" | "RS" | "RC";

export type CsfScopeCatalogItem = {
  code: string;
  title: string;
  outcome: string;
  category_code: string;
  category_name: string;
  function_code: CsfFunctionCode;
  nist_function: string;
  function_name_mn: string;
  is_mandatory: boolean;
};

export const CSF_FUNCTIONS: Array<{
  code: CsfFunctionCode;
  name: string;
  name_mn: string;
}> = [
  { code: "GV", name: "Govern", name_mn: "Засаглал" },
  { code: "ID", name: "Identify", name_mn: "Таних" },
  { code: "PR", name: "Protect", name_mn: "Хамгаалах" },
  { code: "DE", name: "Detect", name_mn: "Илрүүлэх" },
  { code: "RS", name: "Respond", name_mn: "Хариу үйлдэл" },
  { code: "RC", name: "Recover", name_mn: "Сэргээх" },
];

export const CSF_CATEGORY_NAMES: Record<string, string> = {
  "GV.OC": "Organizational Context",
  "GV.RM": "Risk Management Strategy",
  "GV.RR": "Roles, Responsibilities, and Authorities",
  "GV.PO": "Policy",
  "GV.OV": "Oversight",
  "GV.SC": "Cybersecurity Supply Chain Risk Management",
  "ID.AM": "Asset Management",
  "ID.RA": "Risk Assessment",
  "ID.IM": "Improvement",
  "PR.AA": "Identity Management, Authentication, and Access Control",
  "PR.AT": "Awareness and Training",
  "PR.DS": "Data Security",
  "PR.PS": "Platform Security",
  "PR.IR": "Technology Infrastructure Resilience",
  "DE.CM": "Continuous Monitoring",
  "DE.AE": "Adverse Event Analysis",
  "RS.MA": "Incident Management",
  "RS.AN": "Incident Analysis",
  "RS.CO": "Incident Response Reporting and Communication",
  "RS.MI": "Incident Mitigation",
  "RC.RP": "Incident Recovery Plan Execution",
  "RC.CO": "Incident Recovery Communication",
};

export const MANDATORY_SUBCATEGORY_IDS = new Set([
  "GV.OC-01",
  "GV.OC-03",
  "GV.OC-04",
  "GV.RM-01",
  "GV.RM-02",
  "GV.RM-06",
  "GV.RR-01",
  "GV.RR-02",
  "GV.PO-01",
  "GV.PO-02",
  "GV.SC-05",
  "GV.SC-07",
  "ID.AM-01",
  "ID.AM-02",
  "ID.AM-05",
  "ID.RA-01",
  "ID.RA-02",
  "ID.RA-04",
  "ID.RA-05",
  "ID.RA-06",
  "PR.AA-01",
  "PR.AA-03",
  "PR.AA-05",
  "PR.AT-01",
  "PR.DS-01",
  "PR.DS-02",
  "PR.PS-01",
  "PR.PS-04",
  "DE.CM-01",
  "DE.CM-09",
  "DE.AE-03",
  "DE.AE-08",
  "RS.MA-01",
  "RS.MA-03",
  "RS.CO-02",
  "RS.MI-01",
  "RC.RP-01",
  "RC.RP-03",
]);

export const FUNCTION_BY_CODE = Object.fromEntries(
  CSF_FUNCTIONS.map((fn) => [fn.code, fn]),
) as Record<
  CsfFunctionCode,
  { code: CsfFunctionCode; name: string; name_mn: string }
>;

export function getFunctionCode(categoryCode: string): CsfFunctionCode {
  const code = categoryCode.slice(0, 2) as CsfFunctionCode;
  return FUNCTION_BY_CODE[code] ? code : "GV";
}

export function normalizeScopeStatus(
  value: unknown,
  fallback: CsfScopeStatus = "undecided",
): CsfScopeStatus {
  return value === "in_scope" ||
    value === "out_of_scope" ||
    value === "undecided"
    ? value
    : fallback;
}
