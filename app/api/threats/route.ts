import { pool } from "@/lib/db";
import { getAssetTypeMappingNames } from "@/lib/asset-type-mapping";
import { NextRequest, NextResponse } from "next/server";

const THREAT_NAME_ALIASES: Record<string, string[]> = {
  "Brute Force / Credential Stuffing": [
    "Brute Force / Credential Stuffing",
    "Brute Force Attack",
    "Credential Stuffing",
    "Credential Reuse / Password Spraying",
  ],
  "Phishing / Spear Phishing": [
    "Phishing / Spear Phishing",
    "Phishing Email Attack",
    "Spear Phishing",
    "Social Engineering",
  ],
  "Cross-Site Scripting (XSS)": [
    "Cross-Site Scripting (XSS)",
    "Cross-Site Scripting",
  ],
  "Denial of Service (DoS / DDoS)": [
    "Denial of Service (DoS / DDoS)",
    "Denial of Service",
    "Distributed Denial of Service",
  ],
  "Man-in-the-Middle (MitM)": [
    "Man-in-the-Middle (MitM)",
    "Man-in-the-Middle Attack",
    "Network Sniffing",
    "Wireless Eavesdropping",
  ],
  "Malware / Trojan": [
    "Malware / Trojan",
    "Malware Infection",
    "Endpoint Malware via USB",
    "Mobile Device Compromise",
  ],
  "API Key / Token Exposure": ["API Key / Token Exposure", "API Key Exposure"],
  "Weak Encryption / No Encryption": [
    "Weak Encryption / No Encryption",
    "Weak Encryption",
  ],
  "Shadow IT / Unauthorised Access": [
    "Shadow IT / Unauthorised Access",
    "Shadow IT Usage",
    "Unauthorized Remote Access",
  ],
  "Log Tampering / Evidence Destruction": [
    "Log Tampering / Evidence Destruction",
    "Log Tampering",
  ],
  "Backup Failure / Corruption": [
    "Backup Failure / Corruption",
    "Backup Failure",
  ],
  Misconfiguration: [
    "Misconfiguration",
    "Cloud Misconfiguration",
    "VPN Split Tunneling Exploitation",
  ],
  "Account Takeover": ["Account Takeover", "Session Hijacking"],
  "Unpatched Vulnerabilities": [
    "Unpatched Vulnerabilities",
    "Operating System Failure",
    "Application Software Failure",
  ],
};

const normalizeThreatName = (value: string) => value.trim().toLowerCase();

function getThreatIdsForMapping(
  threatIdsByName: Record<string, number[]>,
  threatName: string,
) {
  const aliases = THREAT_NAME_ALIASES[threatName] ?? [threatName];
  return Array.from(
    new Set(
      aliases.flatMap(
        (alias) => threatIdsByName[normalizeThreatName(alias)] ?? [],
      ),
    ),
  );
}

// ── Schema + seed ──────────────────────────────────────────────────────────

async function ensureThreatsSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS asset_types (
      id SERIAL PRIMARY KEY,
      type_name VARCHAR(100) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS threats (
      id SERIAL PRIMARY KEY,
      threat_name VARCHAR(255) NOT NULL,
      description TEXT,
      threat_type VARCHAR(100),
      likelihood_level INTEGER DEFAULT 3,
      potential_impact VARCHAR(50),
      nist_category VARCHAR(100),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS asset_threat_mapping (
      id SERIAL PRIMARY KEY,
      asset_type_id INTEGER REFERENCES asset_types(id) ON DELETE CASCADE,
      threat_id INTEGER REFERENCES threats(id) ON DELETE CASCADE,
      risk_level VARCHAR(50) DEFAULT 'Medium',
      mitigation_notes TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(asset_type_id, threat_id)
    )
  `);

  await pool.query(
    `ALTER TABLE threats ADD COLUMN IF NOT EXISTS description_mn TEXT`,
  );
  await pool.query(
    `ALTER TABLE asset_threat_mapping ADD COLUMN IF NOT EXISTS mitigation_notes_mn TEXT`,
  );

  // Seed threats if the table is empty
  const count = await pool.query("SELECT COUNT(*) FROM threats");
  if (parseInt(count.rows[0].count) === 0) {
    await pool.query(`
      INSERT INTO threats (threat_name, description, threat_type, likelihood_level, potential_impact, nist_category) VALUES
      ('Brute Force / Credential Stuffing',    'Automated attempts to guess passwords or reuse leaked credentials to gain unauthorised access.',                          'Attack',         4, 'High',     'PR.AA'),
      ('Phishing / Spear Phishing',             'Deceptive emails or messages that trick users into revealing credentials or installing malware.',                         'Human',          4, 'High',     'PR.AT'),
      ('SQL Injection',                         'Malicious SQL statements inserted into input fields to manipulate or exfiltrate database content.',                       'Application',    4, 'Critical', 'PR.DS'),
      ('Cross-Site Scripting (XSS)',            'Injection of malicious scripts into web pages viewed by other users, enabling session hijack or data theft.',             'Application',    3, 'High',     'PR.DS'),
      ('Ransomware',                            'Malware that encrypts files and demands payment for the decryption key, causing operational disruption.',                 'Malware',        3, 'Critical', 'RC.RP'),
      ('Insider Threat',                        'Malicious or negligent actions by employees, contractors, or partners with legitimate access.',                           'Human',          3, 'High',     'PR.AA'),
      ('Denial of Service (DoS / DDoS)',        'Flooding a service with traffic to exhaust resources and make it unavailable to legitimate users.',                       'Availability',   3, 'High',     'PR.IR'),
      ('Man-in-the-Middle (MitM)',              'Attacker intercepts communications between two parties to eavesdrop or alter data in transit.',                           'Network',        3, 'High',     'PR.DS'),
      ('Privilege Escalation',                  'Exploiting misconfigurations or vulnerabilities to gain higher-level access than originally granted.',                    'Attack',         3, 'Critical', 'PR.AA'),
      ('Supply Chain Compromise',               'Tampering with software, hardware, or services from a third-party vendor before delivery.',                               'Third-Party',    2, 'Critical', 'ID.SC'),
      ('Zero-Day Exploit',                      'Exploitation of an unknown or unpatched vulnerability before the vendor has issued a fix.',                               'Vulnerability',  2, 'Critical', 'DE.CM'),
      ('Misconfiguration',                      'Insecure default settings, open storage buckets, or exposed admin interfaces that enable unauthorised access.',           'Configuration',  4, 'High',     'PR.DS'),
      ('Data Exfiltration',                     'Unauthorised transfer of sensitive data to an external location by an attacker or malicious insider.',                    'Data',           3, 'Critical', 'PR.DS'),
      ('Malware / Trojan',                      'Malicious software disguised as legitimate programs that can steal data, create backdoors, or cause damage.',             'Malware',        3, 'High',     'DE.CM'),
      ('API Key / Token Exposure',              'Sensitive API keys or tokens hardcoded in code, logs, or public repositories, enabling unauthorised access.',             'Application',    4, 'High',     'PR.DS'),
      ('Unpatched Vulnerabilities',             'Known CVEs that remain unpatched, providing attackers with documented exploitation paths.',                               'Vulnerability',  4, 'High',     'PR.IP'),
      ('Weak Encryption / No Encryption',       'Sensitive data stored or transmitted without adequate encryption, exposing it to interception or theft.',                 'Cryptography',   3, 'High',     'PR.DS'),
      ('Account Takeover',                      'Attacker gains full control of a legitimate user account through credential theft, SIM swap, or session hijack.',         'Attack',         3, 'Critical', 'PR.AA'),
      ('Shadow IT / Unauthorised Access',       'Use of unapproved applications or services that bypass organisational security controls and monitoring.',                  'Access Control', 3, 'Medium',   'ID.AM'),
      ('Log Tampering / Evidence Destruction',  'Attacker modifies or deletes audit logs to hide malicious activity and hinder incident response.',                        'Monitoring',     2, 'High',     'DE.AE'),
      ('Backup Failure / Corruption',           'Backups are incomplete, untested, or corrupted, preventing recovery after data loss or ransomware attack.',               'Availability',   3, 'Critical', 'RC.RP'),
      ('Social Engineering',                    'Psychological manipulation of individuals into performing actions or divulging confidential information.',                 'Human',          4, 'High',     'PR.AT'),
      ('Container Escape',                      'Attacker breaks out of a container sandbox to access the host system or other containers.',                               'Configuration',  2, 'Critical', 'PR.IR'),
      ('DNS Hijacking',                         'Manipulation of DNS records to redirect users to malicious sites or intercept traffic.',                                  'Network',        2, 'High',     'PR.IR'),
      ('Credential Reuse / Password Spraying',  'Using the same credentials across multiple services, or trying a few common passwords against many accounts.',            'Attack',         4, 'High',     'PR.AA')
    `);
  }

  // Upsert Mongolian descriptions for all seeded threats
  const MN_DESCRIPTIONS: Record<string, string> = {
    "Brute Force / Credential Stuffing":
      "Нууц үгийг автоматаар таах эсвэл алдагдсан нэвтрэх мэдээллийг ашиглан зөвшөөрөлгүй нэвтрэх оролдлого хийдэг халдлага.",
    "Phishing / Spear Phishing":
      "Хэрэглэгчдийг нэвтрэх мэдээллээ задруулах эсвэл хортой програм суулгахад хуурах зорилготой хуурамч имэйл эсвэл зурвас.",
    "SQL Injection":
      "Мэдээллийн сангийн агуулгыг удирдах эсвэл хулгайлахын тулд оруулах хэсэгт хортой SQL тушаал оруулах халдлага.",
    "Cross-Site Scripting (XSS)":
      "Бусад хэрэглэгчдийн харах вэб хуудсуудад хортой скрипт оруулах замаар сэшн хулгайлах эсвэл өгөгдөл хулгайлах боломж олгодог халдлага.",
    Ransomware:
      "Файлуудыг шифрлэж, тайлах түлхүүрийн хариуд төлбөр шаардах, үйл ажиллагааны тасалдал үүсгэдэг хортой програм.",
    "Insider Threat":
      "Хууль ёсны нэвтрэх эрх бүхий ажилтан, гэрээт ажилтан эсвэл түншийн хорлонтой буюу хайхрамжгүй үйлдэл.",
    "Denial of Service (DoS / DDoS)":
      "Хэрэглэгчдэд үйлчилгээ хүртэхгүй байлгахын тулд нөөцийг дуусгаж системд хэт их трафик илгээх халдлага.",
    "Man-in-the-Middle (MitM)":
      "Халдагч хоёр талын харилцааны завсарт орж дамжилт дахь өгөгдлийг чагнах эсвэл өөрчлөх.",
    "Privilege Escalation":
      "Анх олгогдсоноос өндөр эрхийг авахын тулд буруу тохиргоо эсвэл эмзэг байдлыг ашиглах.",
    "Supply Chain Compromise":
      "Гуравдагч талын нийлүүлэгчийн программ хангамж, техник хангамж эсвэл үйлчилгээг хүргэлтийн өмнө тооцсон оролцоо.",
    "Zero-Day Exploit":
      "Постачлагч засварыг гаргахаас өмнө тодорхойгүй буюу засагдаагүй эмзэг байдлыг ашиглах халдлага.",
    Misconfiguration:
      "Зөвшөөрөлгүй нэвтрэх боломж олгодог аюулгүй бус өгөгдмөл тохиргоо, нийтэд нээлттэй хадгалалт эсвэл ил гарсан удирдлагын интерфэйс.",
    "Data Exfiltration":
      "Халдагч эсвэл хорлонтой дотоод хүний зөвшөөрөлгүйгээр нууц өгөгдлийг гадаад байршил руу дамжуулах.",
    "Malware / Trojan":
      "Өгөгдөл хулгайлах, арын нэвтрэлтийн цонх үүсгэх эсвэл хохирол учруулдаг хууль ёсны програм мэт харагдах хортой програм.",
    "API Key / Token Exposure":
      "Кодод, логт эсвэл нийтийн репозиторид хатуу кодлогдсон нууц API түлхүүр эсвэл токен нь зөвшөөрөлгүй нэвтрэх боломж олгодог.",
    "Unpatched Vulnerabilities":
      "Засагдаагүй хэвээр байгаа алдартай эмзэг байдлууд нь халдагчдад документлагдсан ашиглалтын зам бүрдүүлдэг.",
    "Weak Encryption / No Encryption":
      "Нууц өгөгдлийг хангалттай шифрлэлтгүйгээр хадгалах эсвэл дамжуулах нь чагнах эсвэл хулгайлах эрсдэлд өртүүлдэг.",
    "Account Takeover":
      "Халдагч нэвтрэх мэдээлэл хулгайлах, SIM своп эсвэл сэшн хулгайгаар хэрэглэгчийн бүртгэлийг бүрэн хяналтандаа авах.",
    "Shadow IT / Unauthorised Access":
      "Байгууллагын аюулгүй байдлын хяналт, мониторингийг тойрч гардаг зөвшөөрөлгүй програм эсвэл үйлчилгээ ашиглах.",
    "Log Tampering / Evidence Destruction":
      "Халдагч аудитын бүртгэлийг өөрчилж устгаж хорлонтой үйлдлийг нуун, инцидентийн хариу арга хэмжээнд саад учруулах.",
    "Backup Failure / Corruption":
      "Нөөцлөлт дутуу, туршаагүй эсвэл эвдэрсэн тул өгөгдлийн алдагдал эсвэл ransomware халдлагын дараа сэргээх боломжгүй болох.",
    "Social Engineering":
      "Нууц мэдээлэл задруулах эсвэл тодорхой үйлдэл хийлгэхэд хүмүүсийг сэтгэлзүйн аргаар уруу татах.",
    "Container Escape":
      "Халдагч контейнерийн хамгаалалтаас гарч эзэн систем эсвэл бусад контейнерт нэвтрэх.",
    "DNS Hijacking":
      "DNS бүртгэлийг өөрчилж хэрэглэгчдийг хортой сайт руу чиглүүлэх эсвэл трафик чагнах.",
    "Credential Reuse / Password Spraying":
      "Олон үйлчилгээнд ижил нэвтрэх мэдээлэл ашиглах эсвэл олон бүртгэлийн эсрэг хэдхэн түгээмэл нууц үг туршин нэвтрэх оролдлого.",
  };
  for (const [name, mn] of Object.entries(MN_DESCRIPTIONS)) {
    await pool.query(
      `UPDATE threats SET description_mn = $1 WHERE lower(threat_name) = lower($2) AND (description_mn IS NULL OR description_mn = '')`,
      [mn, name],
    );
  }

  // Ensure all asset_types exist (upsert by name so mappings can reference them)
  const typeNames = [
    "Database",
    "Application",
    "Network",
    "Endpoint Fleet",
    "Identity Provider",
    "API",
    "Infrastructure",
    "SaaS Tenant",
    "Message Queue",
    "Cache System",
    "File Storage",
    "Backup System",
    "Monitoring/Logging",
    "VPN/Remote Access",
    "Load Balancer",
    "Container Orchestration",
    "Web Server",
    "Email System",
    "Collaboration Platform",
    "Hardware",
    "Software",
    "Data",
    "Cloud",
  ];
  for (const name of typeNames) {
    await pool.query(
      `INSERT INTO asset_types (type_name) VALUES ($1) ON CONFLICT (type_name) DO NOTHING`,
      [name],
    );
  }

  // Build threat_id map
  const threatRows = await pool.query("SELECT id, threat_name FROM threats");
  const tId: Record<string, number[]> = {};
  for (const threatRow of threatRows.rows) {
    const normalizedName = normalizeThreatName(threatRow.threat_name);
    tId[normalizedName] = [...(tId[normalizedName] ?? []), threatRow.id];
  }

  // Build asset_type_id map
  const atRows = await pool.query("SELECT id, type_name FROM asset_types");
  const atId: Record<string, number> = {};
  for (const r of atRows.rows) atId[r.type_name] = r.id;

  // Mappings: [asset_type, threat_name, risk_level, mitigation_note]
  const mappings: [string, string, string, string][] = [
    // Database
    [
      "Database",
      "SQL Injection",
      "Critical",
      "Use parameterised queries and ORM; never interpolate user input into SQL.",
    ],
    [
      "Database",
      "Brute Force / Credential Stuffing",
      "High",
      "Enforce strong passwords, MFA, and account lockout on DB accounts.",
    ],
    [
      "Database",
      "Data Exfiltration",
      "Critical",
      "Restrict network access to DB; audit all queries; encrypt data at rest.",
    ],
    [
      "Database",
      "Privilege Escalation",
      "High",
      "Apply least-privilege to all DB roles; review grants regularly.",
    ],
    [
      "Database",
      "Misconfiguration",
      "High",
      "Disable default accounts; restrict public access; harden DB config.",
    ],
    [
      "Database",
      "Unpatched Vulnerabilities",
      "High",
      "Apply DB engine patches promptly; subscribe to vendor security advisories.",
    ],
    [
      "Database",
      "Backup Failure / Corruption",
      "Critical",
      "Test backups regularly; store copies off-site; verify restore procedures.",
    ],

    // Application
    [
      "Application",
      "SQL Injection",
      "Critical",
      "Use parameterised queries; validate all inputs; apply WAF rules.",
    ],
    [
      "Application",
      "Cross-Site Scripting (XSS)",
      "High",
      "Sanitise output; use Content-Security-Policy headers; validate inputs.",
    ],
    [
      "Application",
      "API Key / Token Exposure",
      "High",
      "Store secrets in a vault; scan repos for credentials; rotate keys regularly.",
    ],
    [
      "Application",
      "Unpatched Vulnerabilities",
      "High",
      "Maintain a dependency inventory; apply patches within SLA windows.",
    ],
    [
      "Application",
      "Misconfiguration",
      "High",
      "Use Infrastructure-as-Code with security linting; review config before deploy.",
    ],
    [
      "Application",
      "Privilege Escalation",
      "Critical",
      "Enforce least-privilege; validate authorisation on every request.",
    ],

    // Network
    [
      "Network",
      "Man-in-the-Middle (MitM)",
      "High",
      "Enforce TLS 1.2+ everywhere; use certificate pinning for critical APIs.",
    ],
    [
      "Network",
      "Denial of Service (DoS / DDoS)",
      "High",
      "Deploy DDoS mitigation service; rate-limit at edge; over-provision capacity.",
    ],
    [
      "Network",
      "DNS Hijacking",
      "High",
      "Enable DNSSEC; monitor DNS records for unexpected changes.",
    ],
    [
      "Network",
      "Misconfiguration",
      "High",
      "Audit firewall rules regularly; remove unused open ports.",
    ],
    [
      "Network",
      "Malware / Trojan",
      "High",
      "Deploy IDS/IPS; segment network to limit lateral movement.",
    ],

    // Endpoint Fleet
    [
      "Endpoint Fleet",
      "Malware / Trojan",
      "High",
      "Deploy EDR on all endpoints; keep AV signatures current.",
    ],
    [
      "Endpoint Fleet",
      "Ransomware",
      "Critical",
      "Enable EDR; block macro execution; maintain tested offline backups.",
    ],
    [
      "Endpoint Fleet",
      "Phishing / Spear Phishing",
      "High",
      "Train users regularly; deploy email filtering; use anti-phishing MFA.",
    ],
    [
      "Endpoint Fleet",
      "Unpatched Vulnerabilities",
      "High",
      "Enforce automatic OS and app updates; maintain patch compliance metrics.",
    ],
    [
      "Endpoint Fleet",
      "Insider Threat",
      "High",
      "Monitor endpoint activity; enforce DLP policies; review access rights.",
    ],

    // Identity Provider
    [
      "Identity Provider",
      "Brute Force / Credential Stuffing",
      "Critical",
      "Enable MFA for all accounts; implement adaptive authentication.",
    ],
    [
      "Identity Provider",
      "Account Takeover",
      "Critical",
      "Enforce phishing-resistant MFA (passkeys/FIDO2); monitor for anomalous logins.",
    ],
    [
      "Identity Provider",
      "Privilege Escalation",
      "Critical",
      "Enforce separation of duties; review privileged roles monthly.",
    ],
    [
      "Identity Provider",
      "Phishing / Spear Phishing",
      "High",
      "Deploy DMARC/DKIM/SPF; train users; use hardware security keys.",
    ],
    [
      "Identity Provider",
      "Misconfiguration",
      "High",
      "Audit federation settings and conditional access policies regularly.",
    ],

    // API
    [
      "API",
      "API Key / Token Exposure",
      "Critical",
      "Rotate keys regularly; use short-lived tokens; scan repos for secrets.",
    ],
    [
      "API",
      "Brute Force / Credential Stuffing",
      "High",
      "Implement rate limiting and IP-based throttling on all endpoints.",
    ],
    [
      "API",
      "SQL Injection",
      "Critical",
      "Validate and sanitise all input; use parameterised queries in backend.",
    ],
    [
      "API",
      "Misconfiguration",
      "High",
      "Disable unused endpoints; enforce HTTPS; validate CORS origins strictly.",
    ],
    [
      "API",
      "Man-in-the-Middle (MitM)",
      "High",
      "Enforce TLS; validate server certificates; use certificate transparency.",
    ],

    // Infrastructure
    [
      "Infrastructure",
      "Misconfiguration",
      "Critical",
      "Use IaC with security checks; enforce least-privilege IAM policies.",
    ],
    [
      "Infrastructure",
      "Unpatched Vulnerabilities",
      "High",
      "Patch OS and middleware within defined SLA; use vulnerability scanning.",
    ],
    [
      "Infrastructure",
      "Privilege Escalation",
      "Critical",
      "Apply least-privilege; use PAM solutions for privileged access.",
    ],
    [
      "Infrastructure",
      "Ransomware",
      "Critical",
      "Segment networks; maintain tested immutable backups; deploy EDR.",
    ],
    [
      "Infrastructure",
      "Supply Chain Compromise",
      "High",
      "Verify software integrity (checksums/signatures); vet vendors.",
    ],

    // SaaS Tenant
    [
      "SaaS Tenant",
      "Misconfiguration",
      "High",
      "Review sharing settings, data retention, and guest access regularly.",
    ],
    [
      "SaaS Tenant",
      "Account Takeover",
      "High",
      "Enforce MFA; review OAuth app permissions; monitor sign-in logs.",
    ],
    [
      "SaaS Tenant",
      "Data Exfiltration",
      "High",
      "Enable DLP; restrict external sharing; monitor bulk-download activity.",
    ],
    [
      "SaaS Tenant",
      "Shadow IT / Unauthorised Access",
      "Medium",
      "Maintain an approved-app registry; use a CASB solution.",
    ],
    [
      "SaaS Tenant",
      "Supply Chain Compromise",
      "High",
      "Review third-party integrations; audit OAuth grants quarterly.",
    ],

    // Message Queue
    [
      "Message Queue",
      "Misconfiguration",
      "High",
      "Restrict topic/queue access to authorised services only; disable public access.",
    ],
    [
      "Message Queue",
      "Data Exfiltration",
      "High",
      "Encrypt messages at rest and in transit; audit consumer permissions.",
    ],
    [
      "Message Queue",
      "Denial of Service (DoS / DDoS)",
      "High",
      "Implement message rate limits and dead-letter queues to prevent flooding.",
    ],

    // Cache System
    [
      "Cache System",
      "Misconfiguration",
      "High",
      "Bind cache to loopback or VPC; require authentication; disable dangerous commands.",
    ],
    [
      "Cache System",
      "Data Exfiltration",
      "High",
      "Avoid storing sensitive data in cache; encrypt sensitive cached values.",
    ],
    [
      "Cache System",
      "Brute Force / Credential Stuffing",
      "Medium",
      "Require strong auth; block unauthenticated access from public networks.",
    ],

    // File Storage
    [
      "File Storage",
      "Data Exfiltration",
      "Critical",
      "Enforce bucket/container policies; disable public access; log all access.",
    ],
    [
      "File Storage",
      "Misconfiguration",
      "Critical",
      "Audit ACLs; block public read; enable versioning and MFA delete.",
    ],
    [
      "File Storage",
      "Ransomware",
      "High",
      "Enable object versioning; maintain cross-region backups; monitor for bulk deletes.",
    ],
    [
      "File Storage",
      "Insider Threat",
      "High",
      "Restrict access by role; log and alert on bulk downloads.",
    ],

    // Backup System
    [
      "Backup System",
      "Backup Failure / Corruption",
      "Critical",
      "Test restore procedures monthly; verify backup integrity automatically.",
    ],
    [
      "Backup System",
      "Ransomware",
      "Critical",
      "Store immutable, air-gapped backups; keep copies offline.",
    ],
    [
      "Backup System",
      "Data Exfiltration",
      "High",
      "Encrypt all backup data; restrict access to backup infrastructure.",
    ],
    [
      "Backup System",
      "Misconfiguration",
      "High",
      "Audit backup schedules and retention policies; alert on backup job failures.",
    ],

    // Monitoring/Logging
    [
      "Monitoring/Logging",
      "Log Tampering / Evidence Destruction",
      "High",
      "Use append-only, tamper-evident log storage; restrict write access.",
    ],
    [
      "Monitoring/Logging",
      "Misconfiguration",
      "High",
      "Ensure all critical systems forward logs; set alerts for missing log sources.",
    ],
    [
      "Monitoring/Logging",
      "Insider Threat",
      "Medium",
      "Restrict who can modify or delete log sources; review access monthly.",
    ],

    // VPN/Remote Access
    [
      "VPN/Remote Access",
      "Brute Force / Credential Stuffing",
      "Critical",
      "Enforce MFA on VPN; implement geo-blocking and adaptive auth.",
    ],
    [
      "VPN/Remote Access",
      "Unpatched Vulnerabilities",
      "Critical",
      "Apply VPN appliance patches immediately; monitor vendor advisories.",
    ],
    [
      "VPN/Remote Access",
      "Man-in-the-Middle (MitM)",
      "High",
      "Use certificate-based auth; enforce split tunnelling policies.",
    ],
    [
      "VPN/Remote Access",
      "Misconfiguration",
      "High",
      "Restrict VPN access to required resources; review split-tunnel config.",
    ],

    // Load Balancer
    [
      "Load Balancer",
      "Denial of Service (DoS / DDoS)",
      "High",
      "Enable DDoS protection at the load balancer; configure rate limits.",
    ],
    [
      "Load Balancer",
      "Misconfiguration",
      "High",
      "Validate health-check endpoints; restrict management interface access.",
    ],
    [
      "Load Balancer",
      "Man-in-the-Middle (MitM)",
      "High",
      "Terminate TLS at the load balancer; enforce strong cipher suites.",
    ],

    // Container Orchestration
    [
      "Container Orchestration",
      "Container Escape",
      "Critical",
      "Keep container runtime and orchestrator patched; use read-only filesystems.",
    ],
    [
      "Container Orchestration",
      "Misconfiguration",
      "Critical",
      "Scan IaC manifests; disable privileged containers; enforce pod security policies.",
    ],
    [
      "Container Orchestration",
      "Privilege Escalation",
      "Critical",
      "Use RBAC; restrict service account permissions; audit role bindings.",
    ],
    [
      "Container Orchestration",
      "Supply Chain Compromise",
      "High",
      "Verify image signatures; use trusted registries; scan images for CVEs.",
    ],

    // Web Server
    [
      "Web Server",
      "Cross-Site Scripting (XSS)",
      "High",
      "Set CSP headers; sanitise all output; use a WAF.",
    ],
    [
      "Web Server",
      "Unpatched Vulnerabilities",
      "High",
      "Apply web server patches promptly; use vulnerability scanning on server configs.",
    ],
    [
      "Web Server",
      "Denial of Service (DoS / DDoS)",
      "High",
      "Use CDN / DDoS mitigation; configure connection limits.",
    ],
    [
      "Web Server",
      "Misconfiguration",
      "High",
      "Disable directory listing; remove default pages; restrict HTTP methods.",
    ],

    // Email System
    [
      "Email System",
      "Phishing / Spear Phishing",
      "Critical",
      "Deploy DMARC, DKIM, SPF; use email security gateway; train users.",
    ],
    [
      "Email System",
      "Malware / Trojan",
      "High",
      "Scan attachments in sandbox; block executable attachment types.",
    ],
    [
      "Email System",
      "Data Exfiltration",
      "High",
      "Enable DLP on outbound email; monitor for unusual forwarding rules.",
    ],
    [
      "Email System",
      "Account Takeover",
      "High",
      "Enforce MFA; monitor for suspicious mail-forwarding rules.",
    ],

    // Collaboration Platform
    [
      "Collaboration Platform",
      "Data Exfiltration",
      "High",
      "Restrict external sharing; enable DLP; audit guest user access.",
    ],
    [
      "Collaboration Platform",
      "Phishing / Spear Phishing",
      "High",
      "Train users; enable link-scanning in messages; restrict external app installs.",
    ],
    [
      "Collaboration Platform",
      "Misconfiguration",
      "High",
      "Review public channel settings; restrict guest access; audit app permissions.",
    ],
    [
      "Collaboration Platform",
      "Account Takeover",
      "High",
      "Enforce MFA; monitor login anomalies; review OAuth integrations.",
    ],

    // Structural, cloud, and environmental events from imported/custom catalogs
    [
      "SaaS Tenant",
      "Multi-Tenant Isolation Failure",
      "Critical",
      "Review tenant isolation controls and provider assurance reports.",
    ],
    [
      "Cloud",
      "Multi-Tenant Isolation Failure",
      "Critical",
      "Review tenant isolation controls and provider assurance reports.",
    ],
    [
      "Identity Provider",
      "Unauthorized Remote Access",
      "High",
      "Require adaptive MFA and alert on unusual sign-in locations.",
    ],
    [
      "VPN/Remote Access",
      "Unauthorized Remote Access",
      "High",
      "Restrict remote access paths and review exposed login surfaces.",
    ],
    [
      "Endpoint Fleet",
      "Mobile Device Compromise",
      "High",
      "Enroll mobile devices in MDM and enforce patch compliance.",
    ],
    [
      "Infrastructure",
      "Operating System Failure",
      "High",
      "Track OS health, patch levels, and failover readiness.",
    ],
    [
      "Endpoint Fleet",
      "Operating System Failure",
      "High",
      "Track OS health, patch levels, and recovery readiness.",
    ],
    [
      "Application",
      "Application Software Failure",
      "High",
      "Use release testing, rollback plans, and runtime monitoring.",
    ],
    [
      "API",
      "Application Software Failure",
      "High",
      "Use release testing, rollback plans, and runtime monitoring.",
    ],
    [
      "Web Server",
      "Application Software Failure",
      "High",
      "Use release testing, rollback plans, and runtime monitoring.",
    ],
    [
      "Database",
      "Disk Failure",
      "High",
      "Monitor storage health and validate restore procedures.",
    ],
    [
      "File Storage",
      "Disk Failure",
      "High",
      "Monitor storage health and validate restore procedures.",
    ],
    [
      "Backup System",
      "Disk Failure",
      "High",
      "Monitor storage health and validate backup redundancy.",
    ],
    [
      "Infrastructure",
      "Processing Hardware Failure",
      "High",
      "Monitor hardware health and maintain failover capacity.",
    ],
    [
      "Hardware",
      "Processing Hardware Failure",
      "High",
      "Monitor hardware health and maintain failover capacity.",
    ],
    [
      "Network",
      "Communications Hardware Failure",
      "High",
      "Monitor network devices and maintain redundant paths.",
    ],
    [
      "Load Balancer",
      "Communications Hardware Failure",
      "High",
      "Monitor network devices and maintain redundant paths.",
    ],
    [
      "Infrastructure",
      "Electrical Power Failure",
      "High",
      "Maintain UPS, generator coverage, and recovery procedures.",
    ],
    [
      "Hardware",
      "Electrical Power Failure",
      "High",
      "Maintain UPS, generator coverage, and recovery procedures.",
    ],
    [
      "Network",
      "Telecommunications Failure",
      "High",
      "Maintain alternate carriers and failover connectivity.",
    ],
    [
      "VPN/Remote Access",
      "Telecommunications Failure",
      "High",
      "Maintain alternate carriers and failover connectivity.",
    ],
    [
      "Infrastructure",
      "Fire Incident",
      "Critical",
      "Maintain disaster recovery plans and off-site backups.",
    ],
    [
      "Hardware",
      "Fire Incident",
      "Critical",
      "Maintain disaster recovery plans and off-site backups.",
    ],
    [
      "Infrastructure",
      "Flood Incident",
      "Critical",
      "Maintain disaster recovery plans and off-site backups.",
    ],
    [
      "Hardware",
      "Flood Incident",
      "Critical",
      "Maintain disaster recovery plans and off-site backups.",
    ],
    [
      "Infrastructure",
      "Earthquake",
      "Critical",
      "Maintain disaster recovery plans and geographic redundancy.",
    ],
    [
      "Hardware",
      "Earthquake",
      "Critical",
      "Maintain disaster recovery plans and geographic redundancy.",
    ],
    [
      "Collaboration Platform",
      "Pandemic Workforce Disruption",
      "High",
      "Maintain remote-work capacity and operational continuity plans.",
    ],
    [
      "VPN/Remote Access",
      "Pandemic Workforce Disruption",
      "High",
      "Maintain remote-work capacity and operational continuity plans.",
    ],
    [
      "Infrastructure",
      "Environmental Control Failure",
      "High",
      "Monitor facility cooling and alert on environmental thresholds.",
    ],
    [
      "Hardware",
      "Environmental Control Failure",
      "High",
      "Monitor facility cooling and alert on environmental thresholds.",
    ],

    // Legacy asset categories used by earlier imports/docs
    [
      "Software",
      "SQL Injection",
      "Critical",
      "Validate inputs and use parameterized queries.",
    ],
    [
      "Software",
      "Cross-Site Scripting (XSS)",
      "High",
      "Sanitize output and enforce CSP headers.",
    ],
    [
      "Software",
      "Unpatched Vulnerabilities",
      "High",
      "Patch software dependencies within SLA windows.",
    ],
    [
      "Software",
      "Misconfiguration",
      "High",
      "Review secure configuration baselines.",
    ],
    [
      "Software",
      "Application Software Failure",
      "High",
      "Use rollback plans and runtime monitoring.",
    ],
    [
      "Data",
      "Data Exfiltration",
      "Critical",
      "Restrict access and monitor bulk data movement.",
    ],
    [
      "Data",
      "Weak Encryption / No Encryption",
      "High",
      "Encrypt sensitive data at rest and in transit.",
    ],
    [
      "Data",
      "Backup Failure / Corruption",
      "Critical",
      "Test restore procedures and backup integrity.",
    ],
    [
      "Hardware",
      "Disk Failure",
      "High",
      "Monitor hardware health and maintain spare capacity.",
    ],
  ];

  for (const [assetTypeName, threatName, riskLevel, note] of mappings) {
    const assetTypeId = atId[assetTypeName];
    const threatIds = getThreatIdsForMapping(tId, threatName);
    if (!assetTypeId || threatIds.length === 0) continue;

    for (const threatId of threatIds) {
      await pool.query(
        `INSERT INTO asset_threat_mapping (asset_type_id, threat_id, risk_level, mitigation_notes)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (asset_type_id, threat_id) DO NOTHING`,
        [assetTypeId, threatId, riskLevel, note],
      );
    }
  }
}

// ── GET handler ────────────────────────────────────────────────────────────

export async function GET(req: NextRequest) {
  try {
    await ensureThreatsSchema();

    const { searchParams } = new URL(req.url);
    const assetTypeId = searchParams.get("assetTypeId");
    const assetType = searchParams.get("assetType");

    if (assetTypeId) {
      const parsedTypeId = Number(assetTypeId);
      if (!Number.isInteger(parsedTypeId) || parsedTypeId <= 0) {
        return NextResponse.json(
          { error: "assetTypeId must be a positive integer" },
          { status: 400 },
        );
      }

      const result = await pool.query(
        `SELECT
          t.id, t.threat_name, t.description, t.description_mn, t.threat_type,
          t.likelihood_level, t.potential_impact, t.nist_category,
          COALESCE(atm.risk_level, 'Unknown') AS risk_level,
          atm.mitigation_notes,
          atm.mitigation_notes_mn,
          true AS is_related
        FROM threats t
        INNER JOIN asset_threat_mapping atm ON t.id = atm.threat_id
        WHERE atm.asset_type_id = $1
        ORDER BY
          CASE WHEN atm.risk_level = 'Critical' THEN 1
               WHEN atm.risk_level = 'High'     THEN 2
               WHEN atm.risk_level = 'Medium'   THEN 3
               WHEN atm.risk_level = 'Low'      THEN 4
               ELSE 5 END,
          t.likelihood_level DESC, t.threat_name`,
        [parsedTypeId],
      );

      return NextResponse.json({
        success: true,
        source: "mapping",
        threats: result.rows,
        count: result.rows.length,
      });
    }

    if (assetType) {
      const normalizedAssetType = assetType.trim();
      const mappingAssetTypes = getAssetTypeMappingNames(normalizedAssetType);

      const result = await pool.query(
        `SELECT
          t.id, t.threat_name, t.description, t.description_mn, t.threat_type,
          t.likelihood_level, t.potential_impact, t.nist_category,
          COALESCE(atm.risk_level, 'Unknown') AS risk_level,
          atm.mitigation_notes,
          atm.mitigation_notes_mn,
          true AS is_related
        FROM threats t
        INNER JOIN asset_threat_mapping atm ON t.id = atm.threat_id
        INNER JOIN asset_types at ON at.id = atm.asset_type_id
        WHERE at.type_name = ANY($1::text[])
        ORDER BY
          CASE WHEN atm.risk_level = 'Critical' THEN 1
               WHEN atm.risk_level = 'High'     THEN 2
               WHEN atm.risk_level = 'Medium'   THEN 3
               WHEN atm.risk_level = 'Low'      THEN 4
               ELSE 5 END,
          t.likelihood_level DESC, t.threat_name`,
        [mappingAssetTypes],
      );

      if (result.rows.length > 0) {
        return NextResponse.json({
          success: true,
          source: "mapping",
          threats: result.rows,
          count: result.rows.length,
        });
      }

      // Fallback: match by threat_type keywords when no direct mapping exists
      const FALLBACK: Record<string, string[]> = {
        Database: [
          "Application",
          "Data",
          "Configuration",
          "Vulnerability",
          "Attack",
        ],
        Application: [
          "Application",
          "Configuration",
          "Vulnerability",
          "Attack",
          "Data",
        ],
        Network: ["Network", "Attack", "Configuration", "Malware"],
        "Endpoint Fleet": [
          "Malware",
          "Human",
          "Configuration",
          "Vulnerability",
        ],
        Identity: ["Attack", "Access Control", "Configuration", "Human"],
        "Identity Provider": [
          "Attack",
          "Access Control",
          "Configuration",
          "Human",
        ],
        Service: [
          "Application",
          "Configuration",
          "Vulnerability",
          "Attack",
          "Availability",
          "Third-Party",
        ],
        API: ["Application", "Attack", "Configuration", "Data"],
        Infrastructure: [
          "Configuration",
          "Vulnerability",
          "Network",
          "Availability",
        ],
        "SaaS Tenant": ["Third-Party", "Configuration", "Data", "Human"],
      };
      const DEFAULT_FALLBACK = [
        "Attack",
        "Application",
        "Configuration",
        "Vulnerability",
        "Data",
        "Network",
        "Malware",
        "Availability",
        "Monitoring",
        "Human",
        "Access Control",
        "Cryptography",
        "Third-Party",
      ];
      const fallbackTypes = FALLBACK[normalizedAssetType] ?? DEFAULT_FALLBACK;

      const fallback = await pool.query(
        `SELECT
          t.id, t.threat_name, t.description, t.description_mn, t.threat_type,
          t.likelihood_level, t.potential_impact, t.nist_category,
          CASE WHEN t.likelihood_level >= 5 THEN 'Critical'
               WHEN t.likelihood_level  = 4 THEN 'High'
               WHEN t.likelihood_level  = 3 THEN 'Medium'
               ELSE 'Low' END AS risk_level,
          NULL::text AS mitigation_notes,
          NULL::text AS mitigation_notes_mn,
          false AS is_related
        FROM threats t
        WHERE t.threat_type = ANY($1::text[])
        ORDER BY t.likelihood_level DESC, t.threat_name
        LIMIT 25`,
        [fallbackTypes],
      );

      return NextResponse.json({
        success: true,
        source: "fallback",
        message: "No direct mappings found. Showing threats by category.",
        threats: fallback.rows,
        count: fallback.rows.length,
      });
    }

    // No filter — return all threats
    const all = await pool.query(
      `SELECT id, threat_name, description, description_mn, threat_type, likelihood_level,
              potential_impact, nist_category,
              CASE WHEN likelihood_level >= 5 THEN 'Critical'
                   WHEN likelihood_level  = 4 THEN 'High'
                   WHEN likelihood_level  = 3 THEN 'Medium'
                   ELSE 'Low' END AS risk_level,
              NULL::text AS mitigation_notes, NULL::text AS mitigation_notes_mn, false AS is_related
       FROM threats
       ORDER BY likelihood_level DESC, threat_name`,
    );

    return NextResponse.json({
      success: true,
      source: "all",
      threats: all.rows,
      count: all.rows.length,
    });
  } catch (error) {
    console.error("Error fetching threats:", error);
    return NextResponse.json(
      { error: "Failed to fetch threats" },
      { status: 500 },
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    await ensureThreatsSchema();
    const { threat_name, description, description_mn, threat_type, likelihood_level, potential_impact, nist_category } =
      await req.json();

    if (!threat_name?.trim()) {
      return NextResponse.json({ error: "threat_name is required" }, { status: 400 });
    }

    const result = await pool.query(
      `INSERT INTO threats (threat_name, description, description_mn, threat_type, likelihood_level, potential_impact, nist_category)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [
        threat_name.trim(),
        description?.trim() || null,
        description_mn?.trim() || null,
        threat_type?.trim() || null,
        Number(likelihood_level) || 3,
        potential_impact?.trim() || null,
        nist_category?.trim() || null,
      ],
    );

    return NextResponse.json({ threat: result.rows[0] }, { status: 201 });
  } catch (error) {
    console.error("Create threat error:", error);
    return NextResponse.json({ error: "Failed to create threat" }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  try {
    await ensureThreatsSchema();
    const { id, threat_name, description, description_mn, threat_type, likelihood_level, potential_impact, nist_category } =
      await req.json();

    if (!id) {
      return NextResponse.json({ error: "id is required" }, { status: 400 });
    }

    const result = await pool.query(
      `UPDATE threats
       SET threat_name = $1, description = $2, description_mn = $3, threat_type = $4,
           likelihood_level = $5, potential_impact = $6, nist_category = $7
       WHERE id = $8 RETURNING *`,
      [
        threat_name?.trim() || null,
        description?.trim() || null,
        description_mn?.trim() || null,
        threat_type?.trim() || null,
        Number(likelihood_level) || 3,
        potential_impact?.trim() || null,
        nist_category?.trim() || null,
        id,
      ],
    );

    if (result.rows.length === 0) {
      return NextResponse.json({ error: "Threat not found" }, { status: 404 });
    }

    return NextResponse.json({ threat: result.rows[0] });
  } catch (error) {
    console.error("Update threat error:", error);
    return NextResponse.json({ error: "Failed to update threat" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const id = searchParams.get("id");

    if (!id) {
      return NextResponse.json({ error: "id is required" }, { status: 400 });
    }

    const result = await pool.query("DELETE FROM threats WHERE id = $1 RETURNING id", [Number(id)]);

    if (result.rows.length === 0) {
      return NextResponse.json({ error: "Threat not found" }, { status: 404 });
    }

    return NextResponse.json({ message: "Threat deleted" });
  } catch (error) {
    console.error("Delete threat error:", error);
    return NextResponse.json({ error: "Failed to delete threat" }, { status: 500 });
  }
}
