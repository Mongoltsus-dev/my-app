import { pool } from "@/lib/db";
import {
  MANAGEMENT_APPROVER_LABEL,
  ROLE_MANAGER,
  getCurrentUser,
} from "@/lib/current-user";
import { MANDATORY_SUBCATEGORY_IDS } from "@/lib/nist-csf-scope";
import { NextRequest, NextResponse } from "next/server";

type PolicyPayload = {
  id?: unknown;
  title?: unknown;
  description?: unknown;
  category?: unknown;
  review_frequency?: unknown;
  nist_ref?: unknown;
  is_required?: unknown;
  required_items?: unknown;
  organization_response?: unknown;
  addressed_requirement_items?: unknown;
  csf_subcategory_ids?: unknown;
  document_note?: unknown;
  created_by?: unknown;
  approved_by?: unknown;
  approve?: unknown; // true = approve, false = reject
  submit?: unknown; // true = submit for approval
};

const FREQUENCY_INTERVAL: Record<string, string> = {
  Monthly: "1 month",
  Quarterly: "3 months",
  Annually: "12 months",
};

function requirements(...items: string[]) {
  return items.map((item) => `- ${item}`).join("\n");
}

const GV_SC_05_REQUIRED_ITEMS = requirements(
  "Мэдээллийн нууцлалын шаардлага - Гуравдагч тал байгууллагын мэдээллийг зөвшөөрөлгүй задруулах, хуулбарлах, бусдад дамжуулахыг хориглох",
  "Өгөгдөл хамгаалах шаардлага - Хувийн мэдээлэл, байгууллагын нууц мэдээлэл, санхүүгийн мэдээлэл зэрэг өгөгдлийг хэрхэн хадгалах, дамжуулах, устгахыг тодорхойлох",
  "Data handling - Data location, subprocessor, retention, deletion/return, breach support зэрэг өгөгдөлтэй харьцах нөхцөлийг тодорхойлох",
  "Хандалтын эрхийн хяналт - Гуравдагч талын ямар ажилтан ямар систем, өгөгдөлд хандах эрхтэй байхыг тодорхойлох",
  "Authentication requirement - Strong password, MFA, account review зэрэг нэвтрэх хамгаалалтын шаардлагыг тусгах",
  "Үүрэг ба хариуцлага - Байгууллага болон гуравдагч талын аюулгүй байдлын үүрэг, хариуцлагыг тодорхой заах",
  "Incident notification - Мэдээлэл алдагдах, халдлага илрэх, сэжигтэй үйлдэл гарах үед хэдэн цагийн дотор мэдэгдэхийг заах",
  "Лог бүртгэл ба мониторинг - Гуравдагч талын системийн үйл ажиллагаа, хандалт, өөрчлөлтийг бүртгэх, хянах шаардлагыг тусгах",
  "Security standard compliance - ISO 27001, NIST CSF, байгууллагын дотоод бодлого зэрэг аюулгүй байдлын шаардлагыг мөрдөхийг заах",
  "Right-to-audit - Байгууллага гуравдагч талын аюулгүй байдлын хэрэгжилтийг шалгах, аудит хийх эрхтэй байхыг тусгах",
  "Security evidence - Security report, certification, penetration test, vulnerability remediation нотолгоо гаргаж өгөх шаардлагыг тусгах",
  "Subprocessor control - Гуравдагч тал өөр дэд ханган нийлүүлэгч ашиглах бол байгууллагаас зөвшөөрөл авах нөхцөлийг тодорхойлох",
  "Data deletion and return - Гэрээ дуусах үед байгууллагын өгөгдлийг буцаах, устгах, устгасан тухай баталгаа өгөхийг заах",
  "Access revocation - Гэрээ дуусах, ажилтан солигдох, үйлчилгээ зогсох үед гуравдагч талын хандалтын эрхийг цуцлах журам",
  "Transition support - Гэрээ дуусах үед өгөгдөл, үйлчилгээ, системийг байгууллага эсвэл шинэ үйлчилгээ үзүүлэгч рүү шилжүүлэхэд дэмжлэг үзүүлэх журам",
  "SLA ба service availability - Үйлчилгээний тасралтгүй ажиллагаа, downtime, backup, recovery time зэрэг шаардлагыг тодорхойлох",
  "Patch ба vulnerability management - Системийн шинэчлэлт, эмзэг байдлын засвар, vulnerability scanning хийх үүргийг тусгах",
  "Breach support - Мэдээллийн аюулгүй байдлын зөрчил гарсан үед шалгалт, нотолгоо, тайлан гаргах, сэргээх ажиллагаанд дэмжлэг үзүүлэх нөхцөл",
  "Гэрээ зөрчсөн тохиолдлын арга хэмжээ - Аюулгүй байдлын шаардлага биелүүлэхгүй бол хандалт хаах, гэрээ цуцлах, нөхөн төлбөр шаардах нөхцөлийг тусгах",
);

const GV_SC_05_DESCRIPTION =
  "Гуравдагч талын үйлчилгээ болон нийлүүлэгчийн гэрээнд хандалтын хамгаалалт, лог бүртгэл, зөрчил мэдэгдэх хугацаа, өгөгдөл хамгаалах, аудит хийх эрх зэрэг аюулгүй байдлын шаардлагыг тодорхойлох бодлого.";

// NIST CSF 2.0 required policies — one per key subcategory
const REQUIRED_POLICIES = [
  {
    nist_ref: "GV.PO-01",
    title: "Мэдээллийн аюулгүй байдлын бодлого",
    description:
      "Байгууллагын кибер аюулгүй байдлын эрсдэлийг удирдах үндсэн бодлого.",
    category: "Мэдээллийн аюулгүй байдал",
    csf_subcategory_ids: "GV.PO-01, GV.PO-02, PR.AA-03, PR.AA-05",
    required_items: requirements(
      "Бодлогын зорилго, хамрах хүрээ, эзэмшигч, батлах эрх, review давтамж",
      "Нууц үгийн доод шаардлага: урт, давтамж, reuse хориг, password manager/MFA ашиглалт",
      "Ажилд орсон, шилжсэн, ажлаас гарсан хэрэглэгчийн эрх олгох/өөрчлөх/цуцлах SLA",
      "Ажлаас гарсан хэрэглэгчийн системийн эрхийг ажлын өдөрт нь, critical системд 4 цагийн дотор хаах шаардлага",
      "Зөрчил мэдээлэх суваг, сахилгын хариуцлага, бодлогын хэрэгжилтийн нотолгоо",
    ),
  },
  {
    nist_ref: "GV.OC-03",
    title: "Зохицуулалт ба гэрээний шаардлагын бүртгэлийн бодлого",
    description:
      "Кибер аюулгүй байдал, нууцлал, гэрээний үүрэгтэй холбоотой хууль, стандарт, харилцагчийн шаардлагыг бүртгэж, хөрөнгө, эрсдэл, хяналттай холбох governance бодлого.",
    category: "Нийцлийн удирдлага",
    csf_subcategory_ids: "GV.OC-03, GV.OC-05",
    required_items: requirements(
      "Хамаарах хууль, стандарт, гэрээ, харилцагчийн шаардлагын бүртгэл",
      "Шаардлага бүрийн эзэмшигч, хамрах бизнес процесс, холбогдох хөрөнгө",
      "Шаардлагыг эрсдэл, хяналт, нотолгоотой холбох аргачлал",
      "Зөрүү илэрсэн үед засварлах төлөвлөгөө, exception батлах журам",
      "Бүртгэлийг шинэчлэх давтамж ба удирдлагад тайлагнах хэлбэр",
    ),
  },
  {
    nist_ref: "GV.RM-02",
    title: "Эрсдэлийн appetite ба tolerance бодлого",
    description:
      "Байгууллагын profile, critical asset tier, data classification, RTO/RPO-д үндэслэн зөвшөөрөх residual risk түвшин, escalation, exception approval шаардлагыг тодорхойлно.",
    category: "Эрсдэлийн менежмент",
    csf_subcategory_ids: "GV.RM-02, GV.RM-04, GV.RM-05",
    required_items: requirements(
      "Risk appetite, tolerance, residual risk acceptance-ийн босго түвшин",
      "Critical asset, sensitive data, RTO/RPO-д суурилсан escalation шалгуур",
      "Өндөр/ноцтой эрсдэлийг хэн батлах, ямар хугацаанд шийдвэрлэх эрх",
      "Exception-ийн хугацаа, нөхцөл, сунгалт, дахин хяналтын шаардлага",
      "KRI/KPI, appetite давсан тохиолдлын тайлагналын давтамж",
    ),
  },
  {
    nist_ref: "GV.RM-01",
    title: "Эрсдэлийн менежментийн бодлого",
    description:
      "Байгууллагын эрсдэлийн менежментийн зорилт, хүрээ, хариуцлагыг тодорхойлсон бодлого.",
    category: "Эрсдэлийн менежмент",
    csf_subcategory_ids: "GV.RM-01, GV.RM-03, GV.RM-06",
    required_items: requirements(
      "Эрсдэл тодорхойлох, үнэлэх, эрэмбэлэх, арга хэмжээ сонгох процесс",
      "Inherent болон residual risk оноо, likelihood/impact матрицын тодорхойлолт",
      "Risk owner, control owner, approver, reviewer-ийн үүрэг хариуцлага",
      "Risk register-д заавал бүртгэх талбар, review давтамж, хаах шалгуур",
      "Residual risk acceptance болон remediation roadmap батлах журам",
    ),
  },
  {
    nist_ref: "GV.OV-01",
    title: "Удирдлагын хяналт ба тайлагналын бодлого",
    description:
      "Кибер эрсдэлийн KPI, RAG status, remediation roadmap, approved exception-уудыг удирдлагад тогтмол тайлагнах, шийдвэрийг баримтжуулах бодлого.",
    category: "Нийцлийн удирдлага",
    csf_subcategory_ids: "GV.OV-01, GV.OV-02, GV.OV-03",
    required_items: requirements(
      "Удирдлагад тайлагнах KPI/KRI, RAG status, maturity болон remediation үзүүлэлт",
      "Тайлангийн давтамж, оролцогчид, шийдвэр баталгаажуулах хэлбэр",
      "Хугацаа хэтэрсэн action, өндөр эрсдэл, exception-ийг escalation хийх журам",
      "Удирдлагын шийдвэр, зөвшөөрөл, даалгаврын audit trail хадгалалт",
      "Стратеги болон бодлогын өөрчлөлт шаардлагатай үед review хийх нөхцөл",
    ),
  },
  {
    nist_ref: "GV.RR-01",
    title: "Хариуцлага болон дүр үүргийн бодлого",
    description:
      "Удирдлагын кибер аюулгүй байдлын эрсдэлд хариуцлага хүлээх, дүр үүргийг тодорхойлсон бодлого.",
    category: "Нийцлийн удирдлага",
    csf_subcategory_ids: "GV.RR-01, GV.RR-02, GV.RR-03, GV.RR-04",
    required_items: requirements(
      "Кибер аюулгүй байдлын RACI: удирдлага, CISO/IT, risk owner, control owner",
      "Policy owner болон control owner-ийн батлах, хэрэгжүүлэх, нотлох үүрэг",
      "Segregation of duties ба privileged action баталгаажуулах шаардлага",
      "Incident, risk acceptance, vendor approval-д оролцох дүрүүд",
      "Орлон гүйцэтгэгч, сургалт, чадварын шаардлага, жил бүрийн review",
    ),
  },
  {
    nist_ref: "PR.AA-01",
    title: "Хандалтын удирдлагын бодлого",
    description:
      "Зөвшөөрөлтэй хэрэглэгч, үйлчилгээ, техник хангамжийн хандалтыг удирдах бодлого. MFA, нууц үг, эрхийн зарчим.",
    category: "Хандалтын удирдлага",
    csf_subcategory_ids: "PR.AA-01, PR.AA-03, PR.AA-05",
    required_items: requirements(
      "Joiner/Mover/Leaver процесс: эрх хүсэх, батлах, өөрчлөх, цуцлах хугацаа",
      "MFA шаардлага, нууц үг/passphrase-ийн урт, reuse, lockout, reset журам",
      "Least privilege, RBAC, privileged account, break-glass account-ийн хяналт",
      "Ажлаас гарсан хэрэглэгчийн эрхийг HR notification-оос хойш ажлын өдөрт нь хаах",
      "Хандалтын эрхийн улирал бүрийн review, зөрүү засварлах нотолгоо",
    ),
  },
  {
    nist_ref: "PR.DS-01",
    title: "Өгөгдлийн хамгааллын бодлого",
    description:
      "Хадгалагдаж байгаа болон дамжуулагдаж байгаа өгөгдлийн шифрлэлт, ангилал, хамгааллыг тодорхойлсон бодлого.",
    category: "Мэдээллийн аюулгүй байдал",
    csf_subcategory_ids: "PR.DS-01, PR.DS-02, PR.DS-10, PR.DS-11",
    required_items: requirements(
      "Мэдээллийн ангилал, label, эзэмшигч, зөвшөөрөгдөх хэрэглээний дүрэм",
      "Өгөгдөл хадгалах болон дамжуулах үеийн шифрлэлтийн шаардлага",
      "Криптограф түлхүүрийн эзэмшил, хадгалалт, rotation, access control",
      "Backup, retention, restore test, secure disposal-ийн хугацаа ба нотолгоо",
      "Sensitive data sharing, DLP, third-party transfer, data minimization журам",
    ),
  },
  {
    nist_ref: "ID.RA-01",
    title: "Эмзэг байдлын удирдлагын бодлого",
    description:
      "Хөрөнгийн эмзэг байдлыг тодорхойлох, үнэлэх, засах үйл явцыг тодорхойлсон бодлого.",
    category: "Эрсдэлийн менежмент",
    csf_subcategory_ids: "ID.RA-01, ID.RA-02, ID.RA-05, ID.RA-08, ID.RA-10",
    required_items: requirements(
      "Эмзэг байдал илрүүлэх эх сурвалж: scanning, pentest, CISA KEV, vendor advisory",
      "CVSS, exploitability, asset criticality, data sensitivity-д суурилсан эрэмбэлэлт",
      "Critical/high/medium эмзэг байдлыг засах SLA ба exception батлах журам",
      "Засварын дараах validation, false positive шийдвэр, risk acceptance нотолгоо",
      "Supplier болон cloud service-ийн эмзэг байдлын хариуцлага, тайлагнал",
    ),
  },
  {
    nist_ref: "DE.CM-01",
    title: "Хяналт ба мониторингийн бодлого",
    description:
      "Сүлжээ, систем, үйл явдлыг хортой үйлдлийн эсрэг хяналт тавих бодлого. SIEM, EDR, лог бүртгэлийн хамрах хүрээ.",
    category: "Мэдээллийн аюулгүй байдал",
    csf_subcategory_ids: "DE.CM-01, DE.CM-03, DE.CM-06, DE.CM-09",
    required_items: requirements(
      "SIEM/EDR-д заавал илгээх log source, admin activity, authentication event",
      "Log retention, time synchronization, integrity protection-ийн шаардлага",
      "Use case, alert severity, triage, escalation, false positive хаах журам",
      "External service болон SaaS log access, incident investigation-д ашиглах эрх",
      "Monitoring coverage-ийн review, blind spot засварлах action plan",
    ),
  },
  {
    nist_ref: "RS.MA-01",
    title: "Зөрчлийн хариу арга хэмжээний бодлого",
    description:
      "Кибер аюулгүй байдлын зөрчлийн хариу арга хэмжээний төлөвлөгөө, дүр үүрэг, харилцааны бодлого.",
    category: "Зөрчлийн хариу арга хэмжээ",
    csf_subcategory_ids: "RS.MA-01, RS.MA-02, RS.MA-03, RS.MA-04, RS.MA-05",
    required_items: requirements(
      "Incident severity ангилал, triage шалгуур, response эхлүүлэх нөхцөл",
      "Incident commander, technical lead, legal/PR/HR, business owner-ийн үүрэг",
      "Дотоод escalation, regulator/customer/vendor notification-ийн хугацаа",
      "Evidence preservation, chain of custody, communication channel-ийн шаардлага",
      "Post-incident review, lesson learned, tabletop exercise-ийн давтамж",
    ),
  },
  {
    nist_ref: "RC.RP-01",
    title: "Сэргээлт ба тасралтгүй ажиллагааны бодлого",
    description:
      "Кибер аюулгүй байдлын зөрчлийн үед болон дараа нь үйл ажиллагааг сэргээх төлөвлөгөө, нөөцлөлт, RTO/RPO зорилт.",
    category: "Нөөцлөлт ба сэргээлт",
    csf_subcategory_ids: "RC.RP-01, RC.RP-02, RC.RP-03, PR.DS-11",
    required_items: requirements(
      "Critical service, asset tier, dependency-д суурилсан сэргээх дараалал",
      "RTO/RPO зорилт, backup frequency, offsite/immutable backup шаардлага",
      "Restore test-ийн давтамж, амжилтын шалгуур, test evidence хадгалалт",
      "Ransomware болон destructive incident-ийн үед clean restore хийх журам",
      "Сэргээх явцын communication, business approval, normal operation-д буцаах шалгуур",
    ),
  },
  {
    nist_ref: "GV.SC-01",
    title: "Нийлүүлэлтийн сүлжээний аюулгүй байдлын бодлого",
    description:
      "Гуравдагч этгээд, нийлүүлэгч, хамтрагч байгууллагуудтай холбоотой кибер аюулгүй байдлын эрсдэлийг удирдах бодлого.",
    category: "Эрсдэлийн менежмент",
    csf_subcategory_ids:
      "GV.SC-01, GV.SC-02, GV.SC-04, GV.SC-06, GV.SC-07, GV.SC-10",
    required_items: requirements(
      "Supplier/SaaS inventory, service owner, data access, criticality, dependency бүртгэл",
      "Onboarding due diligence: security questionnaire, SOC/ISO evidence, privacy review",
      "Нийлүүлэгчийн эрсдэлийн tier, review давтамж, remediation action tracking",
      "Ongoing monitoring: incident, vulnerability, SLA, compliance evidence шинэчлэлт",
      "Exit plan: data return/deletion, access revocation, transition responsibility",
    ),
  },
  {
    nist_ref: "GV.SC-05",
    title: "Гуравдагч талын гэрээний аюулгүй байдлын бодлого",
    description: GV_SC_05_DESCRIPTION,
    category: "Нийцлийн удирдлага",
    csf_subcategory_ids: "GV.SC-05, GV.SC-08, GV.SC-09, GV.SC-10",
    required_items: GV_SC_05_REQUIRED_ITEMS,
  },
] as const;

async function ensurePoliciesSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS policies (
      id                SERIAL PRIMARY KEY,
      title             TEXT NOT NULL,
      description       TEXT,
      category          VARCHAR(100) NOT NULL DEFAULT 'Бусад',
      version           INTEGER NOT NULL DEFAULT 1,
      status            VARCHAR(50) NOT NULL DEFAULT 'Draft',
      review_frequency  VARCHAR(20) NOT NULL DEFAULT 'Quarterly',
      nist_ref          VARCHAR(20),
      is_required       BOOLEAN NOT NULL DEFAULT FALSE,
      required_items    TEXT,
      organization_response TEXT,
      addressed_requirement_items TEXT,
      csf_subcategory_ids TEXT,
      last_reviewed_at  TIMESTAMP,
      next_review_at    TIMESTAMP,
      created_by        INTEGER,
      approved_by       INTEGER,
      approved_at       TIMESTAMP,
      rejection_note    TEXT,
      document_file_path TEXT,
      document_original_name TEXT,
      document_uploaded_at TIMESTAMP,
      document_note     TEXT,
      created_at        TIMESTAMP DEFAULT NOW(),
      updated_at        TIMESTAMP DEFAULT NOW()
    )
  `);

  const cols = [
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS description TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS review_frequency VARCHAR(20) NOT NULL DEFAULT 'Quarterly'",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS nist_ref VARCHAR(20)",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS is_required BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS required_items TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS organization_response TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS addressed_requirement_items TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS csf_subcategory_ids TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS last_reviewed_at TIMESTAMP",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS next_review_at TIMESTAMP",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS created_by INTEGER",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS approved_by INTEGER",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS rejection_note TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_file_path TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_original_name TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_uploaded_at TIMESTAMP",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_note TEXT",
  ];
  for (const col of cols) await pool.query(col);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS csf_scope_subcategories (
      subcategory_id   VARCHAR(20) PRIMARY KEY,
      scope_status     VARCHAR(20) NOT NULL DEFAULT 'undecided',
      exclusion_reason TEXT,
      created_at       TIMESTAMP DEFAULT NOW(),
      updated_at       TIMESTAMP DEFAULT NOW()
    )
  `);

  // Ensure unique index on nist_ref (safe to run repeatedly)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_nist_ref
      ON policies (nist_ref)
     WHERE nist_ref IS NOT NULL
  `);

  // Seed required NIST policies if they don't exist yet (keyed by nist_ref)
  for (const p of REQUIRED_POLICIES) {
    await pool.query(
      `INSERT INTO policies
         (title, description, category, nist_ref, is_required,
          required_items, csf_subcategory_ids, status, version, review_frequency, updated_at)
       SELECT $1, $2, $3, $4::varchar, TRUE, $5, $6, 'Draft', 1, 'Quarterly', NOW()
        WHERE NOT EXISTS (SELECT 1 FROM policies WHERE nist_ref = $4::varchar)`,
      [
        p.title,
        p.description,
        p.category,
        p.nist_ref,
        p.required_items,
        p.csf_subcategory_ids,
      ],
    );

    await pool.query(
      `UPDATE policies
          SET is_required = TRUE,
              required_items =
                CASE
                  WHEN required_items IS NULL OR BTRIM(required_items) = '' THEN $2
                  ELSE required_items
                END,
              csf_subcategory_ids =
                CASE
                  WHEN csf_subcategory_ids IS NULL OR BTRIM(csf_subcategory_ids) = '' THEN $3
                  ELSE csf_subcategory_ids
                END,
              updated_at =
                CASE
                  WHEN required_items IS NULL
                    OR BTRIM(required_items) = ''
                    OR csf_subcategory_ids IS NULL
                    OR BTRIM(csf_subcategory_ids) = ''
                  THEN NOW()
                  ELSE updated_at
                END
        WHERE nist_ref = $1::varchar`,
      [p.nist_ref, p.required_items, p.csf_subcategory_ids],
    );
  }

  // Force-update GV.SC-05 with the expanded 19-item requirements list
  await pool.query(
    `UPDATE policies
        SET required_items = $1, updated_at = NOW()
      WHERE nist_ref = 'GV.SC-05'
        AND (required_items IS NULL OR required_items NOT LIKE '%Мэдээллийн нууцлалын шаардлага%')`,
    [GV_SC_05_REQUIRED_ITEMS],
  );

  await pool.query(
    `UPDATE policies
        SET description = $1,
            category = CASE
              WHEN category = 'Нийцтэй байдлын удирдлага' THEN 'Нийцлийн удирдлага'
              ELSE category
            END,
            updated_at = NOW()
      WHERE nist_ref = 'GV.SC-05'
        AND (
          description IS NULL
          OR BTRIM(description) = ''
          OR description = 'Нийлүүлэгч, SaaS, outsource үйлчилгээний гэрээнд MFA, logging, incident notification, data handling, right-to-audit зэрэг security requirement тусгах бодлого.'
        )`,
    [GV_SC_05_DESCRIPTION],
  );
}

function toStr(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s.length ? s : null;
}

function toInt(v: unknown): number | null {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function toBool(v: unknown): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "string")
    return ["1", "true", "yes"].includes(v.toLowerCase());
  return Boolean(v);
}

function requirementKey(value: string) {
  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

function parseRequirementItems(value: unknown) {
  return String(value ?? "")
    .split(/\r?\n/)
    .map((line) =>
      line
        .replace(/^\s*(?:[-*•]|\d+[.)])\s+/, "")
        .trim(),
    )
    .filter(Boolean);
}

function parseAddressedRequirementItems(value: unknown) {
  if (Array.isArray(value)) {
    return value
      .map((item) => String(item).trim())
      .filter((item) => item.length > 0);
  }

  const text = toStr(value);
  if (!text) return [];

  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) {
      return parsed
        .map((item) => String(item).trim())
        .filter((item) => item.length > 0);
    }
  } catch {
    // Older rows may use plain text; fall through to line parsing.
  }

  return parseRequirementItems(text);
}

function serializeAddressedRequirementItems(value: unknown) {
  const seen = new Set<string>();
  const items = parseAddressedRequirementItems(value).filter((item) => {
    const key = requirementKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return items.length > 0 ? JSON.stringify(items) : null;
}

function hasImplementationEvidence(row: {
  organization_response?: unknown;
  required_items?: unknown;
  addressed_requirement_items?: unknown;
}) {
  if (toStr(row.organization_response)) return true;

  const requiredItems = parseRequirementItems(row.required_items);
  if (requiredItems.length === 0) return false;

  const addressedKeys = new Set(
    parseAddressedRequirementItems(row.addressed_requirement_items).map(
      requirementKey,
    ),
  );
  return requiredItems.every((item) => addressedKeys.has(requirementKey(item)));
}

async function getPolicyById(id: number) {
  const res = await pool.query(
    `SELECT p.*, cu.full_name AS created_by_name,
            CASE
              WHEN p.status = 'Approved' AND p.approved_at IS NOT NULL
                THEN $2
              ELSE NULL
            END AS approved_by_name,
            (p.status = 'Approved' AND p.next_review_at IS NOT NULL AND p.next_review_at < NOW()) AS is_due_for_review
       FROM policies p
       LEFT JOIN users cu ON cu.id = p.created_by
      WHERE p.id = $1`,
    [id, MANAGEMENT_APPROVER_LABEL],
  );
  return res.rows[0] ?? null;
}

// ── GET all policies ────────────────────────────────────────────────────────
export async function GET() {
  try {
    await ensurePoliciesSchema();

    const result = await pool.query(
      `
      WITH scope_state AS (
        SELECT EXISTS (SELECT 1 FROM csf_scope_subcategories) AS has_defined_scope
      ),
      effective_in_scope AS (
        SELECT UNNEST($1::text[]) AS subcategory_id
        UNION
        SELECT UPPER(subcategory_id) AS subcategory_id
          FROM csf_scope_subcategories
         WHERE scope_status = 'in_scope'
      )
      SELECT
        p.id, p.title, p.description, p.category, p.version,
        p.status, p.review_frequency, p.nist_ref, p.is_required,
        p.required_items, p.organization_response, p.addressed_requirement_items,
        p.csf_subcategory_ids,
        p.last_reviewed_at, p.next_review_at,
        p.created_by, p.approved_by, p.approved_at, p.rejection_note,
        p.document_file_path, p.document_original_name,
        p.document_uploaded_at, p.document_note,
        p.created_at, p.updated_at,
        cu.full_name  AS created_by_name,
        CASE
          WHEN p.status = 'Approved' AND p.approved_at IS NOT NULL
            THEN $2
          ELSE NULL
        END AS approved_by_name,
        -- computed: is the policy overdue for review?
        (p.status = 'Approved'
         AND p.next_review_at IS NOT NULL
         AND p.next_review_at < NOW()) AS is_due_for_review
      FROM policies p
      LEFT JOIN users cu ON cu.id = p.created_by
      WHERE
        (SELECT NOT has_defined_scope FROM scope_state)
        OR EXISTS (
          SELECT 1
            FROM regexp_split_to_table(
                   UPPER(CONCAT_WS(',', p.nist_ref, p.csf_subcategory_ids)),
                   '[,\\s]+'
                 ) AS refs(subcategory_id)
            JOIN effective_in_scope scope
              ON scope.subcategory_id = refs.subcategory_id
        )
      ORDER BY
        CASE p.status
          WHEN 'Pending Approval' THEN 1
          WHEN 'Draft'            THEN 2
          WHEN 'Approved'         THEN 3
          ELSE 4
        END,
        p.updated_at DESC
    `,
      [Array.from(MANDATORY_SUBCATEGORY_IDS), MANAGEMENT_APPROVER_LABEL],
    );

    return NextResponse.json({ success: true, policies: result.rows });
  } catch (error) {
    console.error("Policies fetch error:", error);
    return NextResponse.json(
      { message: "Бодлого татаж чадсангүй" },
      { status: 500 },
    );
  }
}

// ── POST create policy ──────────────────────────────────────────────────────
export async function POST(req: NextRequest) {
  try {
    await ensurePoliciesSchema();
    const body = (await req.json()) as PolicyPayload;

    const title = toStr(body.title);
    if (!title) {
      return NextResponse.json(
        { message: "Гарчиг шаардлагатай" },
        { status: 400 },
      );
    }

    const nistRef = toStr(body.nist_ref)?.toUpperCase() ?? null;
    const isRequired = toBool(body.is_required) || Boolean(nistRef);
    const subcategoryIds = toStr(body.csf_subcategory_ids) ?? nistRef;

    if (nistRef) {
      const existing = await pool.query(
        "SELECT id FROM policies WHERE nist_ref = $1",
        [nistRef],
      );

      if (existing.rows[0]?.id) {
        await pool.query(
          `UPDATE policies
              SET title                 = $1,
                  description           = $2,
                  category              = $3,
                  review_frequency      = $4,
                  nist_ref              = $5,
                  is_required           = TRUE,
                  required_items        = $6,
                  organization_response = $7,
                  csf_subcategory_ids   = $8,
                  document_note         = $9,
                  updated_at            = NOW()
            WHERE id = $10`,
          [
            title,
            toStr(body.description),
            toStr(body.category) ?? "Бусад",
            toStr(body.review_frequency) ?? "Quarterly",
            nistRef,
            toStr(body.required_items),
            toStr(body.organization_response),
            subcategoryIds,
            toStr(body.document_note),
            existing.rows[0].id,
          ],
        );
        const policy = await getPolicyById(existing.rows[0].id);
        return NextResponse.json({ success: true, policy }, { status: 200 });
      }
    }

    const result = await pool.query(
      `INSERT INTO policies
         (title, description, category, review_frequency, nist_ref, is_required,
          required_items, organization_response, csf_subcategory_ids, document_note,
          created_by, status, version, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'Draft', 1, NOW())
       RETURNING id`,
      [
        title,
        toStr(body.description),
        toStr(body.category) ?? "Бусад",
        toStr(body.review_frequency) ?? "Quarterly",
        nistRef,
        isRequired,
        toStr(body.required_items),
        toStr(body.organization_response),
        subcategoryIds,
        toStr(body.document_note),
        toInt(body.created_by),
      ],
    );

    const policy = await getPolicyById(result.rows[0].id);
    return NextResponse.json({ success: true, policy }, { status: 201 });
  } catch (error) {
    console.error("Policy create error:", error);
    return NextResponse.json(
      { message: "Бодлого үүсгэж чадсангүй" },
      { status: 500 },
    );
  }
}

// ── PATCH update / submit / approve / reject ────────────────────────────────
export async function PATCH(req: NextRequest) {
  try {
    await ensurePoliciesSchema();
    const body = (await req.json()) as PolicyPayload;
    const id = Number(body.id);

    if (!Number.isInteger(id) || id <= 0) {
      return NextResponse.json(
        { message: "Хүчинтэй ID шаардлагатай" },
        { status: 400 },
      );
    }

    // ── Approve / Reject shortcut ──────────────────────────────────────────
    if (body.approve !== undefined) {
      const isApprove = Boolean(body.approve);
      const approver = await getCurrentUser(req);

      if (!approver) {
        return NextResponse.json(
          { message: "Нэвтэрсэн хэрэглэгч олдсонгүй" },
          { status: 401 },
        );
      }

      if (approver.role_id !== ROLE_MANAGER) {
        return NextResponse.json(
          { message: "Зөвхөн удирдлага дүртэй хэрэглэгч бодлогыг батлах эрхтэй" },
          { status: 403 },
        );
      }

      const approvedById = approver.id;

      if (isApprove) {
        // ── Segregation-of-duties checks ────────────────────────────────
        // Self-approval is forbidden (creator cannot approve their own policy)
        const creatorRow = await pool.query(
          "SELECT created_by FROM policies WHERE id = $1",
          [id],
        );
        if (
          creatorRow.rows[0]?.created_by &&
          creatorRow.rows[0].created_by === approvedById
        ) {
          return NextResponse.json(
            { message: "Өөрийн үүсгэсэн бодлогыг өөрөө батлах боломжгүй (үүрэг хуваарилалт)" },
            { status: 403 },
          );
        }
        // ── End segregation-of-duties checks ────────────────────────────

        // Fetch current frequency to compute next_review_at
        const cur = await pool.query(
          `SELECT review_frequency, document_file_path, organization_response,
                  addressed_requirement_items, required_items, is_required, nist_ref
             FROM policies
            WHERE id = $1`,
          [id],
        );
        if (!cur.rows[0]) {
          return NextResponse.json(
            { message: "Бодлого олдсонгүй" },
            { status: 404 },
          );
        }
        if (!cur.rows[0]?.document_file_path) {
          return NextResponse.json(
            { message: "PDF дүрэм журамгүй бүртгэлийг батлах боломжгүй" },
            { status: 400 },
          );
        }
        if (
          (cur.rows[0]?.is_required || cur.rows[0]?.nist_ref) &&
          !hasImplementationEvidence(cur.rows[0])
        ) {
          return NextResponse.json(
            {
              message:
                "Заавал тусгах бүх зүйлсийг тэмдэглэх шаардлагатай",
            },
            { status: 400 },
          );
        }
        const freq: string = cur.rows[0]?.review_frequency ?? "Quarterly";
        const interval = FREQUENCY_INTERVAL[freq] ?? "3 months";

        await pool.query(
          `UPDATE policies
              SET status           = 'Approved',
                  approved_by      = $1,
                  approved_at      = NOW(),
                  last_reviewed_at = NOW(),
                  next_review_at   = NOW() + INTERVAL '${interval}',
                  rejection_note   = NULL,
                  updated_at       = NOW()
            WHERE id = $2`,
          [approvedById, id],
        );
      } else {
        // Reject → back to Draft
        await pool.query(
          `UPDATE policies
              SET status         = 'Draft',
                  approved_by    = NULL,
                  approved_at    = NULL,
                  updated_at     = NOW()
            WHERE id = $1`,
          [id],
        );
      }

      const policy = await getPolicyById(id);
      return NextResponse.json({ success: true, policy });
    }

    // ── Submit for approval ────────────────────────────────────────────────
    if (body.submit) {
      // Bump version if policy was previously Approved (re-submission after review)
      const cur = await pool.query(
        `SELECT status, version, document_file_path, organization_response,
                addressed_requirement_items, required_items, is_required, nist_ref
           FROM policies
          WHERE id = $1`,
        [id],
      );
      if (!cur.rows[0]?.document_file_path) {
        return NextResponse.json(
          { message: "Баталгаажуулахын өмнө PDF дүрэм журмаа оруулна уу" },
          { status: 400 },
        );
      }
      if (
        (cur.rows[0]?.is_required || cur.rows[0]?.nist_ref) &&
        !hasImplementationEvidence(cur.rows[0])
      ) {
        return NextResponse.json(
          {
            message:
              "Заавал тусгах бүх зүйлсийг тэмдэглэх шаардлагатай",
          },
          { status: 400 },
        );
      }
      const wasApproved = cur.rows[0]?.status === "Approved";
      const nextVersion = wasApproved
        ? (cur.rows[0].version ?? 1) + 1
        : (cur.rows[0]?.version ?? 1);

      await pool.query(
        `UPDATE policies
            SET status     = 'Pending Approval',
                version    = $1,
                updated_at = NOW()
          WHERE id = $2`,
        [nextVersion, id],
      );

      const policy = await getPolicyById(id);
      return NextResponse.json({ success: true, policy });
    }

    // ── Requirement checklist update ───────────────────────────────────────
    if (body.addressed_requirement_items !== undefined) {
      await pool.query(
        `UPDATE policies
            SET addressed_requirement_items = $1,
                updated_at = NOW()
          WHERE id = $2`,
        [serializeAddressedRequirementItems(body.addressed_requirement_items), id],
      );

      const policy = await getPolicyById(id);
      return NextResponse.json({ success: true, policy });
    }

    // ── Regular edit (title, description, category, review_frequency) ──────
    const title = toStr(body.title);
    if (!title) {
      return NextResponse.json(
        { message: "Гарчиг шаардлагатай" },
        { status: 400 },
      );
    }

    const nistRef = toStr(body.nist_ref)?.toUpperCase() ?? null;
    if (nistRef) {
      const conflict = await pool.query(
        "SELECT id FROM policies WHERE nist_ref = $1 AND id <> $2",
        [nistRef, id],
      );
      if (conflict.rows[0]?.id) {
        return NextResponse.json(
          {
            message: `${nistRef} subcategory өөр дүрэм журамтай холбогдсон байна`,
          },
          { status: 409 },
        );
      }
    }

    await pool.query(
      `UPDATE policies
          SET title            = $1,
              description      = $2,
              category         = $3,
              review_frequency = $4,
              nist_ref         = $5,
              is_required      = CASE WHEN $5::varchar IS NOT NULL THEN TRUE ELSE is_required END,
              required_items   = $6,
              organization_response = $7,
              csf_subcategory_ids = $8,
              document_note    = $9,
              updated_at       = NOW()
        WHERE id = $10`,
      [
        title,
        toStr(body.description),
        toStr(body.category) ?? "Бусад",
        toStr(body.review_frequency) ?? "Quarterly",
        nistRef,
        toStr(body.required_items),
        toStr(body.organization_response),
        toStr(body.csf_subcategory_ids) ?? nistRef,
        toStr(body.document_note),
        id,
      ],
    );

    const policy = await getPolicyById(id);
    return NextResponse.json({ success: true, policy });
  } catch (error) {
    console.error("Policy update error:", error);
    return NextResponse.json(
      { message: "Бодлого шинэчилж чадсангүй" },
      { status: 500 },
    );
  }
}

// ── DELETE ──────────────────────────────────────────────────────────────────
export async function DELETE(req: NextRequest) {
  try {
    await ensurePoliciesSchema();
    const { searchParams } = new URL(req.url);
    const id = searchParams.get("id");
    if (!id) {
      return NextResponse.json({ message: "ID шаардлагатай" }, { status: 400 });
    }
    await pool.query("DELETE FROM policies WHERE id = $1", [id]);
    return NextResponse.json({ success: true, deletedId: Number(id) });
  } catch (error) {
    console.error("Policy delete error:", error);
    return NextResponse.json(
      { message: "Бодлого устгаж чадсангүй" },
      { status: 500 },
    );
  }
}
