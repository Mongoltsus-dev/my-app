const ASSET_TYPE_MAPPING_ALIASES: Record<string, string[]> = {
  "information / data asset": ["Database", "File Storage", "Data"],
  "hardware asset": ["Infrastructure", "Hardware", "Network", "Endpoint Fleet"],
  "software asset": ["Application", "Software", "SaaS Tenant"],
  "system / platform": [
    "Application",
    "Infrastructure",
    "API",
    "Service",
    "Database",
  ],
  "network / communication asset": [
    "Infrastructure",
    "Network",
    "Firewall",
    "VPN",
  ],
  "cloud / virtual asset": ["Infrastructure", "Cloud", "SaaS Tenant"],
  "identity / access asset": ["Identity Provider", "Identity"],
  "people / human asset": ["User", "Workforce", "People"],
  "business process asset": ["Business Process", "Service", "Application"],
  "service asset": ["Service", "Application", "API", "SaaS Tenant"],
  "physical / facility asset": ["Facility", "Physical", "Infrastructure"],
  "documentation / knowledge asset": ["Documentation", "Data", "File Storage"],
  "third-party / supplier asset": ["Third Party", "Vendor", "Supplier", "SaaS Tenant"],
  "legal / financial / reputation asset": [
    "Legal",
    "Financial",
    "Reputation",
    "Data",
  ],
  service: ["Application", "Infrastructure", "API", "SaaS Tenant"],
  identity: ["Identity Provider"],
  software: ["Application", "Software"],
  hardware: ["Infrastructure", "Hardware", "Network"],
  data: ["Database", "File Storage", "Data"],
  cloud: ["Infrastructure", "Cloud", "SaaS Tenant"],
};

export function getAssetTypeMappingNames(assetType: string | null | undefined) {
  const cleaned = String(assetType ?? "").trim();
  if (!cleaned) return [];

  const aliases = ASSET_TYPE_MAPPING_ALIASES[cleaned.toLowerCase()] ?? [];
  return Array.from(new Set([cleaned, ...aliases]));
}
