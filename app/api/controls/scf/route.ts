import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

const FUNCTION_CODE_TO_NAME: Record<string, string> = {
  GV: "Govern",
  ID: "Identify",
  PR: "Protect",
  DE: "Detect",
  RS: "Respond",
  RC: "Recover",
};

const FUNCTION_NAME_BY_VALUE: Record<string, string> = {
  govern: "Govern",
  identify: "Identify",
  protect: "Protect",
  detect: "Detect",
  respond: "Respond",
  recover: "Recover",
  засаглал: "Govern",
  таних: "Identify",
  хамгаалах: "Protect",
  илрүүлэх: "Detect",
  "хариу үйлдэл": "Respond",
  сэргээх: "Recover",
};

type RiskContext = {
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  threat_name: string | null;
  inherent_risk_level: string | null;
};

type ControlCandidate = {
  control_id: string;
  domain: string | null;
  control_name: string;
  description: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  priority: string | null;
  implementation_effort: string | null;
  typical_cost: string | null;
  relevance?: number;
};

const CONTROL_MN_COPY: Record<
  string,
  Pick<ControlCandidate, "domain" | "control_name" | "description">
> = {
  "CTL-0003": {
    domain: "Танилт нэвтрэлт ба хандалтын удирдлага",
    control_name: "MFA ба нөхцөлт хандалтын суурь хяналт",
    description:
      "Хэрэглэгч болон админ эрхтэй бүртгэлүүдэд олон хүчин зүйлийн баталгаажуулалт, нөхцөлт хандалтын дүрэм хэрэгжүүлж, нууц үг таах болон эрхгүй нэвтрэх эрсдэлийг бууруулна.",
  },
  "CTL-0004": {
    domain: "Танилт нэвтрэлт ба хандалтын удирдлага",
    control_name: "Өндөр эрхийн хандалтын удирдлага",
    description:
      "Админ эрхийг байнгын нээлттэй байлгахгүй, шаардлагатай үед зөвшөөрөлтэйгээр түр олгох, үүрэг тусгаарлах, өндөр эрхтэй үйлдлийг хянах замаар эрхийн буруу ашиглалтыг багасгана.",
  },
  "CTL-0005": {
    domain: "Танилт нэвтрэлт ба хандалтын удирдлага",
    control_name: "Ажилд орох, шилжих, гарах үеийн бүртгэлийн мөчлөг",
    description:
      "Ажилтны албан тушаал өөрчлөгдөх эсвэл ажлаас гарах үед системийн хандалтыг цаг тухайд нь шинэчлэх, хаах журмыг хэрэгжүүлж, илүүдэл эрх үлдэх эрсдэлийг бууруулна.",
  },
  "CTL-0006": {
    domain: "Танилт нэвтрэлт ба хандалтын удирдлага",
    control_name: "Чухал системийн хандалтын тогтмол хяналт",
    description:
      "Чухал системүүдийн хэрэглэгч, админ эрхийг тогтмол шалгаж, хэрэгцээгүй эсвэл зохисгүй эрхийг устган хамгийн бага эрхийн зарчмыг хадгална.",
  },
  "CTL-0010": {
    domain: "Платформын аюулгүй байдал",
    control_name: "Аюулгүй тохиргооны суурь стандарт",
    description:
      "Сервер, endpoint болон платформуудад аюулгүй тохиргооны стандарт тогтоож мөрдүүлснээр буруу тохиргоо, сул хамгаалалтаас үүдэх эрсдэлийг бууруулна.",
  },
  "CTL-0011": {
    domain: "Платформын аюулгүй байдал",
    control_name: "Эмзэг байдлын удирдлага ба засварлах SLA",
    description:
      "Хөрөнгүүдийг тогтмол scan хийж, илэрсэн эмзэг байдлыг ноцтой байдал болон хөрөнгийн ач холбогдлоор эрэмбэлэн тогтоосон хугацаанд засварлана.",
  },
  "CTL-0012": {
    domain: "Тасралтгүй хяналт",
    control_name: "Endpoint илрүүлэлт ба хариу арга хэмжээний хамрах хүрээ",
    description:
      "Endpoint болон серверүүдэд EDR хамгаалалт байршуулж, сэжигтэй үйлдэл, malware, зөвшөөрөлгүй ажиллагааг илрүүлэн хариу арга хэмжээг хурдан эхлүүлнэ.",
  },
  "CTL-0013": {
    domain: "Мэдлэг олгох ба сургалт",
    control_name: "Имэйлийн хамгаалалт ба phishing эсрэг хяналт",
    description:
      "Имэйлийн хамгаалалт, phishing илрүүлэлт, хэрэглэгчийн сургалт, simulation ашиглан хуурамч холбоос болон credential алдагдах эрсдэлийг бууруулна.",
  },
  "CTL-0016": {
    domain: "Платформын аюулгүй байдал",
    control_name: "Лог төвлөрүүлэлт, хадгалалт ба бүрэн бүтэн байдал",
    description:
      "Аюулгүй байдалтай холбоотой логийг төвлөрүүлэн хадгалж, өөрчлөлтөөс хамгаалснаар халдлага илрүүлэх, шалгах, нотлох ажиллагааг дэмжинэ.",
  },
  "CTL-0019": {
    domain: "Тасралтгүй хяналт",
    control_name: "SOC хяналт ба alert тохируулга",
    description:
      "Аюулгүй байдлын alert-уудыг хянах, ангилах, escalation хийх хугацаа болон tuning журмыг тодорхой болгож, бодит халдлагыг хурдан ялган илрүүлнэ.",
  },
  "CTL-0021": {
    domain: "Инцидентийн удирдлага",
    control_name: "Инцидентэд хариу арга хэмжээний төлөвлөгөө ба playbook",
    description:
      "Ransomware, cloud compromise, мэдээлэл алдагдах зэрэг гол хувилбаруудад зориулсан хариу арга хэмжээний төлөвлөгөө, playbook-ийг бэлтгэж туршина.",
  },
  "CTL-0026": {
    domain: "Сэргээх төлөвлөгөөний хэрэгжилт",
    control_name: "Сэргээх төлөвлөгөө хэрэгжүүлэх ба баталгаажуулах",
    description:
      "Үйлчилгээ тасалдсан үед RTO/RPO зорилтод нийцүүлэн сэргээж, сэргээгдсэн системийн бүрэн бүтэн байдлыг шалгасны дараа хэвийн ажиллагаанд шилжүүлнэ.",
  },
};

const DOMAIN_MN_LABELS: Record<string, string> = {
  "Identity Management, Authentication, and Access Control":
    "Танилт нэвтрэлт ба хандалтын удирдлага",
  "Access Control": "Танилт нэвтрэлт ба хандалтын удирдлага",
  "Identification and Authentication": "Танилт нэвтрэлт ба хандалтын удирдлага",
  "Data Security": "Өгөгдлийн аюулгүй байдал",
  "Media Protection": "Өгөгдлийн аюулгүй байдал",
  "Platform Security": "Платформын аюулгүй байдал",
  "Configuration Management": "Платформын аюулгүй байдал",
  "Continuous Monitoring": "Тасралтгүй хяналт",
  "Audit and Accountability": "Тасралтгүй хяналт",
  "System and Information Integrity": "Тасралтгүй хяналт",
  "Awareness and Training": "Мэдлэг олгох ба сургалт",
  "Incident Management": "Инцидентийн удирдлага",
  "Incident Response": "Инцидентийн удирдлага",
  "Incident Analysis": "Инцидентийн шинжилгээ",
  "Incident Recovery Plan Execution": "Сэргээх төлөвлөгөөний хэрэгжилт",
  "Contingency Planning": "Сэргээх төлөвлөгөөний хэрэгжилт",
  "Asset Management": "Хөрөнгийн удирдлага",
  Improvement: "Сайжруулалт",
  Policy: "Бодлого",
  Planning: "Бодлого",
  "Supply Chain Risk Management": "Нийлүүлэлтийн сүлжээний эрсдэлийн удирдлага",
  "Technology Infrastructure Resilience": "Технологийн дэд бүтцийн тэсвэртэй байдал",
  "Physical and Environmental Protection": "Технологийн дэд бүтцийн тэсвэртэй байдал",
  "Organizational Context": "Байгууллагын нөхцөл байдал",
  "Program Management": "Байгууллагын нөхцөл байдал",
  "Risk Assessment": "Эрсдэлийн үнэлгээ",
  "Personnel Security": "Хүний нөөцийн аюулгүй байдал",
  "Maintenance": "Засвар үйлчилгээ",
  "System and Services Acquisition": "Системийн худалдан авалт",
  "System and Communications Protection": "Сүлжээний хамгаалалт",
  "Assessment, Authorization, and Monitoring": "Үнэлгээ, зөвшөөрөл, хяналт",
  "PII Processing and Transparency": "Хувийн мэдээллийн хамгаалалт",
};

const CONTROL_NAME_MN_BY_ID: Record<string, string> = {
  "AC-1": "Хандалтын удирдлагын бодлого ба журам",
  "AC-2": "Бүртгэлийн удирдлага",
  "AC-3": "Хандалтын зөвшөөрлийн хэрэгжилт",
  "AC-4": "Мэдээллийн урсгалын хяналт",
  "AC-5": "Үүргийн тусгаарлалт",
  "AC-6": "Хамгийн бага эрхийн зарчим",
  "AC-7": "Амжилтгүй нэвтрэлтийн оролдлого",
  "AC-8": "Систем ашиглалтын мэдэгдэл",
  "AC-9": "Өмнөх нэвтрэлтийн мэдэгдэл",
  "AC-10": "Зэрэгцээ сессийн хяналт",
  "AC-11": "Төхөөрөмж түгжих",
  "AC-12": "Сесс дуусгах",
  "AC-13": "Хандалтын хяналтын хяналт ба шалгалт",
  "AC-14": "Таних, баталгаажуулахгүйгээр зөвшөөрөх үйлдлүүд",
  "AC-15": "Автомат тэмдэглэгээ",
  "AC-16": "Аюулгүй байдал ба нууцлалын шинж чанарууд",
  "AC-17": "Алсын хандалт",
  "AC-18": "Утасгүй хандалт",
  "AC-19": "Зөөврийн төхөөрөмжийн хандалтын хяналт",
  "AC-20": "Гадаад систем ашиглалт",
  "AC-21": "Мэдээлэл хуваалцах",
  "AC-22": "Нийтэд нээлттэй контент",
  "AC-23": "Өгөгдөл олборлолтоос хамгаалах",
  "AC-24": "Хандалтын шийдвэр",
  "AC-25": "Лавлах монитор",
  "AT-1": "Мэдлэг олгох ба сургалтын бодлого, журам",
  "AT-2": "Аюулгүй байдлын мэдлэг ба суурь сургалт",
  "AT-3": "Үүрэгт суурилсан сургалт",
  "AT-4": "Сургалтын бүртгэл",
  "AT-5": "Аюулгүй байдлын бүлэг, холбоодтой харилцах",
  "AT-6": "Сургалтын санал хүсэлт",
  "AU-1": "Аудит ба хариуцлагын бодлого, журам",
  "AU-2": "Үйл явдлын лог бүртгэл",
  "AU-3": "Аудитын бүртгэлийн агуулга",
  "AU-4": "Аудитын лог хадгалах багтаамж",
  "AU-5": "Аудитын лог бүртгэлийн доголдолд хариу арга хэмжээ",
  "AU-6": "Аудитын бүртгэл хянах, шинжлэх ба тайлагнах",
  "AU-7": "Аудитын бүртгэлийг нэгтгэх ба тайлан гаргах",
  "AU-8": "Цагийн тэмдэглэгээ",
  "AU-9": "Аудитын мэдээллийн хамгаалалт",
  "AU-10": "Үгүйсгэх боломжгүй баталгаа",
  "AU-11": "Аудитын бүртгэл хадгалалт",
  "AU-12": "Аудитын бүртгэл үүсгэх",
  "AU-13": "Мэдээлэл задрах эсэхийг хянах",
  "AU-14": "Сессийн аудит",
  "AU-15": "Альтернатив аудитын лог бүртгэлийн чадвар",
  "AU-16": "Байгууллага хоорондын аудитын лог бүртгэл",
  "CA-1": "Үнэлгээ, зөвшөөрөл ба хяналтын бодлого, журам",
  "CA-2": "Хяналтын үнэлгээ",
  "CA-3": "Мэдээлэл солилцоо",
  "CA-4": "Аюулгүй байдлын баталгаажуулалт",
  "CA-5": "Арга хэмжээ ба хугацааны төлөвлөгөө",
  "CA-6": "Зөвшөөрөл олгох",
  "CA-7": "Тасралтгүй хяналт",
  "CA-8": "Нэвтрэлтийн тест",
  "CA-9": "Дотоод системийн холболтууд",
  "CM-1": "Тохиргооны удирдлагын бодлого ба журам",
  "CM-2": "Суурь тохиргоо",
  "CM-3": "Тохиргооны өөрчлөлтийн хяналт",
  "CM-4": "Нөлөөллийн шинжилгээ",
  "CM-5": "Өөрчлөлтийн хандалтын хязгаарлалт",
  "CM-6": "Тохиргооны тохируулгууд",
  "CM-7": "Хамгийн бага ажиллагаа",
  "CM-8": "Системийн бүрэлдэхүүн хэсгийн бүртгэл",
  "CM-9": "Тохиргооны удирдлагын төлөвлөгөө",
  "CM-10": "Програм хангамж ашиглалтын хязгаарлалт",
  "CM-11": "Хэрэглэгчийн суулгасан програм хангамж",
  "CM-12": "Мэдээллийн байршил",
  "CM-13": "Өгөгдлийн үйлдлийн зураглал",
  "CM-14": "Гарын үсэгтэй бүрэлдэхүүн хэсгүүд",
  "CP-1": "Тасралтгүй ажиллагааны төлөвлөлтийн бодлого ба журам",
  "CP-2": "Тасралтгүй ажиллагааны төлөвлөгөө",
  "CP-3": "Тасралтгүй ажиллагааны сургалт",
  "CP-4": "Тасралтгүй ажиллагааны төлөвлөгөөний туршилт",
  "CP-5": "Тасралтгүй ажиллагааны төлөвлөгөө шинэчлэх",
  "CP-6": "Альтернатив хадгалалтын байр",
  "CP-7": "Альтернатив боловсруулалтын байр",
  "CP-8": "Харилцаа холбооны үйлчилгээ",
  "CP-9": "Системийн нөөцлөлт",
  "CP-10": "Систем сэргээх ба дахин байгуулах",
  "CP-11": "Альтернатив харилцаа холбооны протокол",
  "CP-12": "Аюулгүй горим",
  "CP-13": "Альтернатив аюулгүй байдлын механизм",
  "IA-1": "Таних ба баталгаажуулалтын бодлого, журам",
  "IA-2": "Байгууллагын хэрэглэгчийг таних ба баталгаажуулах",
  "IA-3": "Төхөөрөмжийг таних ба баталгаажуулах",
  "IA-4": "Танигчийн удирдлага",
  "IA-5": "Баталгаажуулагчийн удирдлага",
  "IA-6": "Баталгаажуулалтын хариу мэдээлэл",
  "IA-7": "Криптограф модулийн баталгаажуулалт",
  "IA-8": "Байгууллагын бус хэрэглэгчийг таних ба баталгаажуулах",
  "IA-9": "Үйлчилгээг таних ба баталгаажуулах",
  "IA-10": "Дасан зохицох баталгаажуулалт",
  "IA-11": "Дахин баталгаажуулах",
  "IA-12": "Биеийн байцаалт баталгаажуулах",
  "IR-1": "Инцидентэд хариу арга хэмжээний бодлого ба журам",
  "IR-2": "Инцидентэд хариу арга хэмжээний сургалт",
  "IR-3": "Инцидентэд хариу арга хэмжээний туршилт",
  "IR-4": "Инцидент боловсруулах",
  "IR-5": "Инцидентийн хяналт",
  "IR-6": "Инцидент тайлагнах",
  "IR-7": "Инцидентэд хариу арга хэмжээний тусламж",
  "IR-8": "Инцидентэд хариу арга хэмжээний төлөвлөгөө",
  "IR-9": "Мэдээлэл асгарсан үед авах арга хэмжээ",
  "IR-10": "Инцидентийн шинжилгээ",
  "MA-1": "Засвар үйлчилгээний бодлого ба журам",
  "MA-2": "Хяналттай засвар үйлчилгээ",
  "MA-3": "Засвар үйлчилгээний хэрэгсэл",
  "MA-4": "Алсын засвар үйлчилгээ",
  "MA-5": "Засвар үйлчилгээний ажилтан",
  "MA-6": "Цаг тухайд нь засвар үйлчилгээ хийх",
  "MA-7": "Талбай дээрх засвар үйлчилгээ",
  "MP-1": "Медиа хамгаалалтын бодлого ба журам",
  "MP-2": "Медиа хандалт",
  "MP-3": "Медиа тэмдэглэгээ",
  "MP-4": "Медиа хадгалалт",
  "MP-5": "Медиа тээвэрлэлт",
  "MP-6": "Медиа цэвэрлэгээ",
  "MP-7": "Медиа ашиглалт",
  "MP-8": "Медиа ангилал бууруулах",
  "PE-1": "Физик ба орчны хамгаалалтын бодлого, журам",
  "PE-2": "Физик хандалтын зөвшөөрөл",
  "PE-3": "Физик хандалтын хяналт",
  "PE-4": "Дамжуулалтын хандалтын хяналт",
  "PE-5": "Гаралтын төхөөрөмжийн хандалтын хяналт",
  "PE-6": "Физик хандалтын хяналт-шинжилгээ",
  "PE-7": "Зочны хяналт",
  "PE-8": "Зочны хандалтын бүртгэл",
  "PE-9": "Цахилгаан тоног төхөөрөмж ба кабель",
  "PE-10": "Яаралтай унтраалт",
  "PE-11": "Яаралтай цахилгаан тэжээл",
  "PE-12": "Яаралтай гэрэлтүүлэг",
  "PE-13": "Галын хамгаалалт",
  "PE-14": "Орчны хяналт",
  "PE-15": "Усны гэмтлээс хамгаалах",
  "PE-16": "Хүргэлт ба гаргалт",
  "PE-17": "Альтернатив ажлын байр",
  "PE-18": "Системийн бүрэлдэхүүн хэсгийн байршил",
  "PE-19": "Мэдээлэл алдагдал",
  "PE-20": "Хөрөнгийн хяналт ба мөрдөлт",
  "PE-21": "Цахилгаан соронзон импульсээс хамгаалах",
  "PE-22": "Бүрэлдэхүүн хэсгийн тэмдэглэгээ",
  "PE-23": "Байгууламжийн байршил",
  "PL-1": "Төлөвлөлтийн бодлого ба журам",
  "PL-2": "Системийн аюулгүй байдал ба нууцлалын төлөвлөгөө",
  "PL-3": "Системийн аюулгүй байдлын төлөвлөгөө шинэчлэх",
  "PL-4": "Зан үйлийн дүрэм",
  "PL-5": "Нууцлалын нөлөөллийн үнэлгээ",
  "PL-6": "Аюулгүй байдалтай холбоотой үйл ажиллагааны төлөвлөлт",
  "PL-7": "Үйл ажиллагааны үзэл баримтлал",
  "PL-8": "Аюулгүй байдал ба нууцлалын архитектур",
  "PL-9": "Төвлөрсөн удирдлага",
  "PL-10": "Суурь сонголт",
  "PL-11": "Суурь тохируулга",
  "PM-1": "Мэдээллийн аюулгүй байдлын хөтөлбөрийн төлөвлөгөө",
  "PM-2": "Мэдээллийн аюулгүй байдлын хөтөлбөрийн удирдлагын үүрэг",
  "PM-3": "Мэдээллийн аюулгүй байдал ба нууцлалын нөөц",
  "PM-4": "Арга хэмжээ ба хугацааны төлөвлөгөөний процесс",
  "PM-5": "Системийн бүртгэл",
  "PM-6": "Гүйцэтгэлийн хэмжүүр",
  "PM-7": "Байгууллагын архитектур",
  "PM-8": "Чухал дэд бүтцийн төлөвлөгөө",
  "PM-9": "Эрсдэлийн удирдлагын стратеги",
  "PM-10": "Зөвшөөрлийн процесс",
  "PM-11": "Эрхэм зорилго ба бизнес процессын тодорхойлолт",
  "PM-12": "Дотоод аюулын хөтөлбөр",
  "PM-13": "Аюулгүй байдал ба нууцлалын хүний нөөц",
  "PM-14": "Туршилт, сургалт ба хяналт",
  "PM-15": "Аюулгүй байдал ба нууцлалын бүлэг, холбоод",
  "PM-16": "Аюулын мэдлэг олгох хөтөлбөр",
  "PM-17": "Гадаад систем дээрх хяналттай ангилагдаагүй мэдээллийг хамгаалах",
  "PM-18": "Нууцлалын хөтөлбөрийн төлөвлөгөө",
  "PM-19": "Нууцлалын хөтөлбөрийн удирдлагын үүрэг",
  "PM-20": "Нууцлалын хөтөлбөрийн мэдээллийг түгээх",
  "PM-21": "Задруулалтын бүртгэл",
  "PM-22": "Хувийн мэдээллийн чанарын удирдлага",
  "PM-23": "Өгөгдлийн засаглалын нэгж",
  "PM-24": "Өгөгдлийн бүрэн бүтэн байдлын зөвлөл",
  "PM-25": "Туршилт, сургалт, судалгаанд ашиглах хувийн мэдээллийг багасгах",
  "PM-26": "Гомдлын удирдлага",
  "PM-27": "Нууцлалын тайлагнал",
  "PM-28": "Эрсдэлийн хүрээ тогтоох",
  "PM-29": "Эрсдэлийн удирдлагын хөтөлбөрийн удирдлагын үүрэг",
  "PM-30": "Нийлүүлэлтийн сүлжээний эрсдэлийн удирдлагын стратеги",
  "PM-31": "Тасралтгүй хяналтын стратеги",
  "PM-32": "Зориулалт тодорхойлох",
  "PS-1": "Хүний нөөцийн аюулгүй байдлын бодлого ба журам",
  "PS-2": "Албан тушаалын эрсдэлийн ангилал",
  "PS-3": "Ажилтны шалгалт",
  "PS-4": "Ажилтны ажлаас гаралт",
  "PS-5": "Ажилтны шилжилт",
  "PS-6": "Хандалтын гэрээ",
  "PS-7": "Гадны ажилтны аюулгүй байдал",
  "PS-8": "Ажилтанд авах сахилгын арга хэмжээ",
  "PS-9": "Албан тушаалын тодорхойлолт",
  "PT-1": "Хувийн мэдээлэл боловсруулах ба ил тод байдлын бодлого, журам",
  "PT-2": "Хувийн мэдээлэл боловсруулах эрх",
  "PT-3": "Хувийн мэдээлэл боловсруулах зорилго",
  "PT-4": "Зөвшөөрөл",
  "PT-5": "Нууцлалын мэдэгдэл",
  "PT-6": "Бүртгэлийн системийн мэдэгдэл",
  "PT-7": "Хувийн мэдээллийн тусгай ангилал",
  "PT-8": "Компьютерийн тулгалтын шаардлага",
  "RA-1": "Эрсдэлийн үнэлгээний бодлого ба журам",
  "RA-2": "Аюулгүй байдлын ангилал",
  "RA-3": "Эрсдэлийн үнэлгээ",
  "RA-4": "Эрсдэлийн үнэлгээ шинэчлэх",
  "RA-5": "Эмзэг байдлын хяналт ба скан",
  "RA-6": "Техникийн тандалтын эсрэг арга хэмжээний судалгаа",
  "RA-7": "Эрсдэлийн хариу арга хэмжээ",
  "RA-8": "Нууцлалын нөлөөллийн үнэлгээ",
  "RA-9": "Чухал байдлын шинжилгээ",
  "RA-10": "Аюулын идэвхтэй хайлт",
  "SA-1": "Систем ба үйлчилгээ худалдан авах бодлого, журам",
  "SA-2": "Нөөцийн хуваарилалт",
  "SA-3": "Систем хөгжүүлэх амьдралын мөчлөг",
  "SA-4": "Худалдан авалтын процесс",
  "SA-5": "Системийн баримтжуулалт",
  "SA-6": "Програм хангамж ашиглалтын хязгаарлалт",
  "SA-7": "Хэрэглэгчийн суулгасан програм хангамж",
  "SA-8": "Аюулгүй байдал ба нууцлалын инженерчлэлийн зарчим",
  "SA-9": "Гадаад системийн үйлчилгээ",
  "SA-10": "Хөгжүүлэгчийн тохиргооны удирдлага",
  "SA-11": "Хөгжүүлэгчийн туршилт ба үнэлгээ",
  "SA-12": "Нийлүүлэлтийн сүлжээний хамгаалалт",
  "SA-13": "Найдвартай байдал",
  "SA-14": "Чухал байдлын шинжилгээ",
  "SA-15": "Хөгжүүлэлтийн процесс, стандарт ба хэрэгсэл",
  "SA-16": "Хөгжүүлэгчээс өгөх сургалт",
  "SA-17": "Хөгжүүлэгчийн аюулгүй байдал, нууцлалын архитектур ба дизайн",
  "SA-18": "Хөндлөн өөрчлөлтөөс хамгаалах ба илрүүлэх",
  "SA-19": "Бүрэлдэхүүн хэсгийн жинхэнэ байдал",
  "SA-20": "Чухал бүрэлдэхүүн хэсгийг тусгайлан хөгжүүлэх",
  "SA-21": "Хөгжүүлэгчийн шалгалт",
  "SA-22": "Дэмжлэггүй системийн бүрэлдэхүүн хэсгүүд",
  "SA-23": "Тусгай зориулалтаар тохируулах",
  "SC-1": "Систем ба харилцаа холбооны хамгаалалтын бодлого, журам",
  "SC-2": "Систем ба хэрэглэгчийн ажиллагааг тусгаарлах",
  "SC-3": "Аюулгүй байдлын функцийн тусгаарлалт",
  "SC-4": "Хуваалцсан системийн нөөц дэх мэдээлэл",
  "SC-5": "Үйлчилгээг саатуулах халдлагаас хамгаалах",
  "SC-6": "Нөөцийн хүртээмж",
  "SC-7": "Хилийн хамгаалалт",
  "SC-8": "Дамжуулалтын нууцлал ба бүрэн бүтэн байдал",
  "SC-9": "Дамжуулалтын нууцлал",
  "SC-10": "Сүлжээний холболтыг таслах",
  "SC-11": "Итгэмжлэгдсэн зам",
  "SC-12": "Криптограф түлхүүр байгуулах ба удирдах",
  "SC-13": "Криптограф хамгаалалт",
  "SC-14": "Нийтийн хандалтын хамгаалалт",
  "SC-15": "Хамтын тооцооллын төхөөрөмж ба аппликейшн",
  "SC-16": "Аюулгүй байдал ба нууцлалын шинж чанарын дамжуулалт",
  "SC-17": "Нийтийн түлхүүрийн дэд бүтцийн гэрчилгээ",
  "SC-18": "Зөөврийн код",
  "SC-19": "Интернет протокол дээрх дуу хоолой",
  "SC-20": "Нэр, хаяг шийдвэрлэх аюулгүй үйлчилгээ - эрх бүхий эх сурвалж",
  "SC-21": "Нэр, хаяг шийдвэрлэх аюулгүй үйлчилгээ - рекурсив эсвэл кэш resolver",
  "SC-22": "Нэр, хаяг шийдвэрлэх үйлчилгээний архитектур ба хангалт",
  "SC-23": "Сессийн жинхэнэ байдал",
  "SC-24": "Мэдэгдэж буй төлөвт доголдох",
  "SC-25": "Нимгэн зангилаанууд",
  "SC-26": "Хуурамч объектууд",
  "SC-27": "Платформоос үл хамаарах аппликейшн",
  "SC-28": "Амарсан төлөв дэх мэдээллийн хамгаалалт",
  "SC-29": "Олон төрлийн байдал",
  "SC-30": "Нуун далдлалт ба төөрөгдүүлэх",
  "SC-31": "Далд сувгийн шинжилгээ",
  "SC-32": "Системийн хуваалт",
  "SC-33": "Дамжуулалт бэлтгэлийн бүрэн бүтэн байдал",
  "SC-34": "Өөрчлөх боломжгүй гүйцэтгэх програмууд",
  "SC-35": "Гадаад хортой кодыг таних",
  "SC-36": "Тархсан боловсруулалт ба хадгалалт",
  "SC-37": "Үндсэн сувгаас гадуурх сувгууд",
  "SC-38": "Үйл ажиллагааны аюулгүй байдал",
  "SC-39": "Процессын тусгаарлалт",
  "SC-40": "Утасгүй холбоосын хамгаалалт",
  "SC-41": "Порт ба оролт, гаралтын төхөөрөмжийн хандалт",
  "SC-42": "Мэдрэгчийн чадвар ба өгөгдөл",
  "SC-43": "Ашиглалтын хязгаарлалт",
  "SC-44": "Детонацийн орчин",
  "SC-45": "Системийн цагийн синхрончлол",
  "SC-46": "Домэйн хоорондын бодлогын хэрэгжилт",
  "SC-47": "Альтернатив харилцаа холбооны замууд",
  "SC-48": "Мэдрэгчийг шилжүүлэн байрлуулах",
  "SC-49": "Тоног төхөөрөмжөөр хэрэгжүүлэх тусгаарлалт ба бодлогын хэрэгжилт",
  "SC-50": "Програм хангамжаар хэрэгжүүлэх тусгаарлалт ба бодлогын хэрэгжилт",
  "SC-51": "Тоног төхөөрөмжид суурилсан хамгаалалт",
  "SI-1": "Систем ба мэдээллийн бүрэн бүтэн байдлын бодлого, журам",
  "SI-2": "Алдаа дутагдлыг засварлах",
  "SI-3": "Хортой кодоос хамгаалах",
  "SI-4": "Системийн хяналт",
  "SI-5": "Аюулгүй байдлын анхааруулга, зөвлөмж ба заавар",
  "SI-6": "Аюулгүй байдал ба нууцлалын функцийн баталгаажуулалт",
  "SI-7": "Програм, firmware ба мэдээллийн бүрэн бүтэн байдал",
  "SI-8": "Спамаас хамгаалах",
  "SI-9": "Мэдээлэл оруулах хязгаарлалт",
  "SI-10": "Мэдээлэл оруулах баталгаажуулалт",
  "SI-11": "Алдааны боловсруулалт",
  "SI-12": "Мэдээллийн удирдлага ба хадгалалт",
  "SI-13": "Урьдчилан таамаглах боломжтой доголдлоос сэргийлэх",
  "SI-14": "Тогтмол бус хадгалалт",
  "SI-15": "Мэдээллийн гаралтын шүүлтүүр",
  "SI-16": "Санах ойн хамгаалалт",
  "SI-17": "Доголдлын үед аюулгүй ажиллагааны журам",
  "SI-18": "Хувийн мэдээллийн чанарын ажиллагаа",
  "SI-19": "Танигдах боломжгүй болгох",
  "SI-20": "Өгөгдөл тэмдэглэх",
  "SI-21": "Мэдээлэл шинэчлэх",
  "SI-22": "Мэдээллийн олон эх сурвалж",
  "SI-23": "Мэдээллийн хэсэгчлэл",
  "SR-1": "Нийлүүлэлтийн сүлжээний эрсдэлийн бодлого ба журам",
  "SR-2": "Нийлүүлэлтийн сүлжээний эрсдэлийн удирдлагын төлөвлөгөө",
  "SR-3": "Нийлүүлэлтийн сүлжээний хяналт ба процессууд",
  "SR-4": "Гарал үүслийн бүртгэл ба хяналт",
  "SR-5": "Худалдан авалтын стратеги, хэрэгсэл ба арга",
  "SR-6": "Нийлүүлэгчийн үнэлгээ ба хяналт",
  "SR-7": "Нийлүүлэлтийн сүлжээний үйл ажиллагааны аюулгүй байдал",
  "SR-8": "Мэдэгдлийн гэрээ, тохиролцоо",
  "SR-9": "Хөндлөн өөрчлөлтөөс хамгаалах ба илрүүлэх",
  "SR-10": "Систем эсвэл бүрэлдэхүүн хэсгийг шалгах",
  "SR-11": "Бүрэлдэхүүн хэсгийн жинхэнэ байдал",
  "SR-12": "Бүрэлдэхүүн хэсгийг устгах",
};

const CONTROL_NAME_MN_LABELS: Record<string, string> = {
  "Policy and Procedures": "Бодлого ба журам",
  Withdrawn: "Хүчингүй болсон",
  "Allocation of Resources": "Нөөцийн хуваарилалт",
  "System Development Life Cycle": "Систем хөгжүүлэх амьдралын мөчлөг",
  "Acquisition Process": "Худалдан авалтын процесс",
  "System Documentation": "Системийн баримтжуулалт",
  "Software Usage Restrictions": "Програм хангамж ашиглалтын хязгаарлалт",
  "User-installed Software": "Хэрэглэгчийн суулгасан програм хангамж",
  "Security and Privacy Engineering Principles":
    "Аюулгүй байдал ба нууцлалын инженерчлэлийн зарчим",
  "External System Services": "Гадаад системийн үйлчилгээ",
  "Developer Configuration Management": "Хөгжүүлэгчийн тохиргооны удирдлага",
  "Developer Testing and Evaluation": "Хөгжүүлэгчийн туршилт ба үнэлгээ",
  "Supply Chain Protection": "Нийлүүлэлтийн сүлжээний хамгаалалт",
  Trustworthiness: "Найдвартай байдал",
  "Criticality Analysis": "Чухал байдлын шинжилгээ",
  "Development Process, Standards, and Tools":
    "Хөгжүүлэлтийн процесс, стандарт ба хэрэгсэл",
  "Developer-provided Training": "Хөгжүүлэгчээс өгөх сургалт",
  "Developer Security and Privacy Architecture and Design":
    "Хөгжүүлэгчийн аюулгүй байдал, нууцлалын архитектур ба дизайн",
  "Tamper Resistance and Detection":
    "Хөндлөн өөрчлөлтөөс хамгаалах ба илрүүлэх",
  "Component Authenticity": "Бүрэлдэхүүн хэсгийн жинхэнэ байдал",
  "Customized Development of Critical Components":
    "Чухал бүрэлдэхүүн хэсгийг тусгайлан хөгжүүлэх",
  "Developer Screening": "Хөгжүүлэгчийн шалгалт",
  "Unsupported System Components": "Дэмжлэггүй системийн бүрэлдэхүүн хэсгүүд",
  Specialization: "Тусгай зориулалтаар тохируулах",
  "Supply Chain Risk Management Plan":
    "Нийлүүлэлтийн сүлжээний эрсдэлийн удирдлагын төлөвлөгөө",
  "Supply Chain Controls and Processes":
    "Нийлүүлэлтийн сүлжээний хяналт ба процессууд",
  Provenance: "Гарал үүслийн бүртгэл ба хяналт",
  "Acquisition Strategies, Tools, and Methods":
    "Худалдан авалтын стратеги, хэрэгсэл ба арга",
  "Supplier Assessments and Reviews": "Нийлүүлэгчийн үнэлгээ ба хяналт",
  "Supply Chain Operations Security":
    "Нийлүүлэлтийн сүлжээний үйл ажиллагааны аюулгүй байдал",
  "Notification Agreements": "Мэдэгдлийн гэрээ, тохиролцоо",
  "Inspection of Systems or Components":
    "Систем эсвэл бүрэлдэхүүн хэсгийг шалгах",
  "Component Disposal": "Бүрэлдэхүүн хэсгийг устгах",
};

const FALLBACK_CONTROLS: ControlCandidate[] = [
  {
    control_id: "CTL-0003",
    domain: "Identity Management, Authentication, and Access Control",
    control_name: "MFA and conditional access baseline",
    description:
      "Enforce MFA and conditional access for workforce identities, with stricter controls for privileged roles and high-risk sign-ins.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.AA",
    priority: "High",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
  {
    control_id: "CTL-0004",
    domain: "Identity Management, Authentication, and Access Control",
    control_name: "Privileged access management",
    description:
      "Control privileged access using just-in-time elevation, approvals, separation of duties, and monitoring.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.AA",
    priority: "High",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
  {
    control_id: "CTL-0005",
    domain: "Identity Management, Authentication, and Access Control",
    control_name: "Joiner-mover-leaver account lifecycle",
    description:
      "Provision, update, and remove access based on authoritative HR records and defined termination/change SLAs.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.AA",
    priority: "Medium",
    implementation_effort: "Medium",
    typical_cost: "Low",
  },
  {
    control_id: "CTL-0006",
    domain: "Identity Management, Authentication, and Access Control",
    control_name: "Access reviews for critical systems",
    description:
      "Perform periodic access reviews for critical systems to verify least privilege and remediate inappropriate access.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.AA",
    priority: "Medium",
    implementation_effort: "Medium",
    typical_cost: "Low",
  },
  {
    control_id: "CTL-0010",
    domain: "Platform Security",
    control_name: "Secure configuration baselines",
    description:
      "Define and enforce secure configuration baselines for servers, endpoints, and platforms.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.PS",
    priority: "High",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
  {
    control_id: "CTL-0011",
    domain: "Platform Security",
    control_name: "Vulnerability management and remediation SLAs",
    description:
      "Scan assets and remediate vulnerabilities within SLAs based on severity and asset criticality.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.PS",
    priority: "High",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
  {
    control_id: "CTL-0012",
    domain: "Continuous Monitoring",
    control_name: "Endpoint detection and response coverage",
    description:
      "Deploy and maintain EDR on endpoints and servers to detect malicious activity and reduce dwell time.",
    nist_csf_function: "Detect",
    nist_csf_category: "DE.CM",
    priority: "High",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
  {
    control_id: "CTL-0013",
    domain: "Awareness and Training",
    control_name: "Email security and phishing protection",
    description:
      "Implement layered email protection, phishing defenses, and user susceptibility tracking.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.AT",
    priority: "Medium",
    implementation_effort: "Low",
    typical_cost: "Low",
  },
  {
    control_id: "CTL-0016",
    domain: "Platform Security",
    control_name: "Centralized logging, retention, and integrity",
    description:
      "Centralize security-relevant logs and protect retention and integrity for investigations and monitoring.",
    nist_csf_function: "Protect",
    nist_csf_category: "PR.PS",
    priority: "Medium",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
  {
    control_id: "CTL-0019",
    domain: "Continuous Monitoring",
    control_name: "SOC monitoring and alert tuning",
    description:
      "Operate monitoring capability with documented alert triage, escalation SLAs, and tuning governance.",
    nist_csf_function: "Detect",
    nist_csf_category: "DE.CM",
    priority: "High",
    implementation_effort: "High",
    typical_cost: "High",
  },
  {
    control_id: "CTL-0021",
    domain: "Incident Management",
    control_name: "Incident response plan and playbooks",
    description:
      "Maintain and test incident response plans and playbooks for priority security scenarios.",
    nist_csf_function: "Respond",
    nist_csf_category: "RS.MA",
    priority: "High",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
  {
    control_id: "CTL-0026",
    domain: "Incident Recovery Plan Execution",
    control_name: "Recovery plan execution and validation",
    description:
      "Restore services according to RTO/RPO and validate recovered assets before returning to normal operations.",
    nist_csf_function: "Recover",
    nist_csf_category: "RC.RP",
    priority: "Medium",
    implementation_effort: "Medium",
    typical_cost: "Medium",
  },
];

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [
    tableName,
  ]);
  return Boolean(result.rows[0]?.name);
}

async function columnExists(tableName: string, columnName: string) {
  const result = await pool.query(
    `SELECT 1
       FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = $1
        AND column_name = $2
      LIMIT 1`,
    [tableName, columnName],
  );
  return result.rows.length > 0;
}

function normalize(value: string | null | undefined) {
  return String(value ?? "").trim().toLowerCase();
}

function resolveFunctionName(risk: RiskContext | null) {
  const categoryCode = risk?.nist_csf_category?.split(".")[0]?.toUpperCase();
  if (categoryCode && FUNCTION_CODE_TO_NAME[categoryCode]) {
    return FUNCTION_CODE_TO_NAME[categoryCode];
  }

  const raw = String(risk?.nist_csf_function ?? "").trim();
  const upper = raw.toUpperCase();
  if (FUNCTION_CODE_TO_NAME[upper]) return FUNCTION_CODE_TO_NAME[upper];

  return FUNCTION_NAME_BY_VALUE[normalize(raw)] ?? raw;
}

function keywordBoost(text: string, threat: string | null) {
  const hay = text.toLowerCase();
  const t = (threat ?? "").toLowerCase();
  let score = 0;
  if (/(account|credential|brute|password|privilege|access)/.test(t)) {
    if (/(identity|access|auth|mfa|credential|privilege|account)/.test(hay)) {
      score += 8;
    }
  }
  if (/(cloud|misconfig|configuration)/.test(t)) {
    if (/(cloud|configuration|baseline|hardening|posture)/.test(hay)) {
      score += 8;
    }
  }
  if (/(phishing|email)/.test(t)) {
    if (/(email|phishing|awareness|training)/.test(hay)) score += 8;
  }
  if (/(ransomware|backup|recovery)/.test(t)) {
    if (/(backup|recovery|restore|incident|response)/.test(hay)) score += 8;
  }
  if (/(logging|monitor|detect)/.test(t)) {
    if (/(logging|monitor|detect|alert|siem)/.test(hay)) score += 8;
  }
  if (/(vulnerab|patch|exploit)/.test(t)) {
    if (/(vulnerab|patch|remediation|scan)/.test(hay)) score += 8;
  }
  return score;
}

function priorityWeight(priority: string | null | undefined) {
  if (priority === "Critical") return 4;
  if (priority === "High") return 3;
  if (priority === "Medium") return 2;
  if (priority === "Low") return 1;
  return 0;
}

function localizeControl(control: ControlCandidate): ControlCandidate {
  const copy = CONTROL_MN_COPY[control.control_id];
  const controlName =
    copy?.control_name ??
    CONTROL_NAME_MN_BY_ID[control.control_id] ??
    CONTROL_NAME_MN_LABELS[control.control_name] ??
    control.control_name;

  if (!copy) {
    const domain =
      DOMAIN_MN_LABELS[control.domain ?? ""] ??
      control.domain ??
      "кибер аюулгүй байдлын хяналт";

    return {
      ...control,
      domain: domain,
      control_name: controlName,
      description: control.description,
    };
  }
  return {
    ...control,
    domain: copy.domain,
    control_name: controlName,
    description: copy.description,
  };
}

async function getRiskContext(riskId: string | null): Promise<RiskContext | null> {
  if (!riskId) return null;

  const hasRiskAnalysis = await tableExists("public.risk_analysis");
  const [
    hasRiskRegisterId,
    hasRiskId,
    hasInherentLevel,
    hasRiskLevel,
  ] = hasRiskAnalysis
    ? await Promise.all([
        columnExists("risk_analysis", "risk_register_id"),
        columnExists("risk_analysis", "risk_id"),
        columnExists("risk_analysis", "inherent_risk_level"),
        columnExists("risk_analysis", "risk_level"),
      ])
    : [false, false, false, false];
  const joinConditions = [
    hasRiskRegisterId ? "ra.risk_register_id = rr.id" : null,
    hasRiskId ? "ra.risk_id = rr.id" : null,
  ].filter(Boolean);
  const analysisJoin =
    hasRiskAnalysis && joinConditions.length > 0
      ? `LEFT JOIN LATERAL (
           SELECT *
             FROM risk_analysis ra
            WHERE ${joinConditions.join(" OR ")}
            ORDER BY ra.id DESC
            LIMIT 1
         ) ra ON true`
      : "";
  const levelExpression =
    hasRiskAnalysis && joinConditions.length > 0
      ? `COALESCE(
           ${hasInherentLevel ? "ra.inherent_risk_level" : "NULL::varchar"},
           ${hasRiskLevel ? "ra.risk_level" : "NULL::varchar"}
         )`
      : "NULL::varchar";

  const { rows } = await pool.query<RiskContext>(
    `SELECT rr.nist_csf_function,
            rr.nist_csf_category,
            t.threat_name,
            ${levelExpression} AS inherent_risk_level
       FROM risk_register rr
       LEFT JOIN threats t ON t.id = rr.threat_id
       ${analysisJoin}
      WHERE rr.id = $1`,
    [Number(riskId)],
  );

  return rows[0] ?? null;
}

async function getNistControls(): Promise<ControlCandidate[]> {
  const catalogTable = (await tableExists("public.nist_controls"))
    ? "nist_controls"
    : (await tableExists("public.nist_control"))
      ? "nist_control"
      : null;
  if (!catalogTable) return [];
  const [
    hasControlId,
    hasScfControlId,
    hasDomain,
    hasScfDomain,
    hasControlName,
    hasScfControlName,
    hasDescription,
    hasScfDescription,
    hasPriority,
    hasActive,
    hasImplNote,
  ] = await Promise.all([
    columnExists(catalogTable, "control_id"),
    columnExists(catalogTable, "scf_control_id"),
    columnExists(catalogTable, "domain"),
    columnExists(catalogTable, "scf_domain"),
    columnExists(catalogTable, "control_name"),
    columnExists(catalogTable, "scf_control_name"),
    columnExists(catalogTable, "description"),
    columnExists(catalogTable, "scf_description"),
    columnExists(catalogTable, "priority"),
    columnExists(catalogTable, "is_active"),
    columnExists(catalogTable, "implementation_note"),
  ]);

  const controlIdExpression = hasControlId
    ? "control_id"
    : hasScfControlId
      ? "scf_control_id"
      : "id::text";
  const domainExpression = hasDomain
    ? "domain"
    : hasScfDomain
      ? "scf_domain"
      : "NULL::varchar";
  const controlNameExpression = hasControlName
    ? "control_name"
    : hasScfControlName
      ? "scf_control_name"
      : "'Нэргүй хяналт'::varchar";
  const descriptionExpression = hasDescription
    ? "description"
    : hasScfDescription
      ? "scf_description"
      : "NULL::text";

  // nist_controls.priority is INT (1=highest). The UI compares against the
  // textual labels Critical/High/Medium/Low, so map at the query layer.
  const priorityExpression = hasPriority
    ? `CASE priority
         WHEN 1 THEN 'Critical'
         WHEN 2 THEN 'High'
         WHEN 3 THEN 'Medium'
         WHEN 4 THEN 'Low'
         ELSE 'Low'
       END`
    : "NULL";

  const { rows } = await pool.query<ControlCandidate>(
    `SELECT ${controlIdExpression} AS control_id,
            ${domainExpression} AS domain,
            ${controlNameExpression} AS control_name,
            ${descriptionExpression} AS description,
            nist_csf_function,
            nist_csf_category,
            ${priorityExpression} AS priority,
            ${hasImplNote ? "implementation_note" : "NULL::text"} AS implementation_effort,
            NULL::varchar AS typical_cost
       FROM ${catalogTable}
      WHERE ${hasActive ? "COALESCE(is_active, true) = true" : "true"}
      ORDER BY ${hasPriority ? "priority ASC NULLS LAST," : ""} ${domainExpression} ASC, ${controlIdExpression} ASC`,
  );

  return rows;
}

function rankControls(controls: ControlCandidate[], risk: RiskContext | null) {
  const fnName = resolveFunctionName(risk);
  const category = risk?.nist_csf_category ?? null;

  return controls
    .map((control) => {
      const text = [
        control.control_id,
        control.domain,
        control.control_name,
        control.description,
        control.nist_csf_function,
        control.nist_csf_category,
      ]
        .filter(Boolean)
        .join(" ");

      let relevance = 0;
      if (category && control.nist_csf_category === category) relevance += 20;
      if (fnName && control.nist_csf_function === fnName) relevance += 10;
      relevance += keywordBoost(text, risk?.threat_name ?? null);

      if (risk?.inherent_risk_level === "Critical") {
        if (control.priority === "Critical" || control.priority === "High") {
          relevance += 3;
        }
      }
      if (risk?.inherent_risk_level === "High" && control.priority === "High") {
        relevance += 2;
      }

      return { ...control, relevance };
    })
    .sort(
      (a, b) =>
        (b.relevance ?? 0) - (a.relevance ?? 0) ||
        priorityWeight(b.priority) - priorityWeight(a.priority) ||
        String(a.domain ?? "").localeCompare(String(b.domain ?? "")) ||
        String(a.control_id).localeCompare(String(b.control_id)),
    );
}

export async function GET(req: NextRequest) {
  try {
    const riskId = req.nextUrl.searchParams.get("risk_id");
    const risk = await getRiskContext(riskId);
    let source = "nist_controls";
    let controls = await getNistControls();
    if (controls.length === 0) {
      source = "built-in";
      controls = FALLBACK_CONTROLS;
    }
    const rankedControls = rankControls(
      controls.map(localizeControl),
      risk,
    );

    return NextResponse.json({
      controls: riskId ? rankedControls.slice(0, 8) : rankedControls,
      source,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to fetch controls";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
