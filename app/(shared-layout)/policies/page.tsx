"use client";

import { useAuth } from "@/app/context/AuthContext";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ClipboardList,
  Clock,
  Download,
  Edit3,
  Eye,
  FileUp,
  Plus,
  RefreshCw,
  Search,
  UploadCloud,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

type Policy = {
  id: number;
  title: string;
  description: string | null;
  category: string;
  version: number;
  status: "Draft" | "Pending Approval" | "Approved";
  review_frequency: "Monthly" | "Quarterly" | "Annually";
  nist_ref: string | null;
  is_required: boolean;
  required_items: string | null;
  organization_response: string | null;
  addressed_requirement_items: string | null;
  csf_subcategory_ids: string | null;
  last_reviewed_at: string | null;
  next_review_at: string | null;
  created_by: number | null;
  created_by_name: string | null;
  approved_by: number | null;
  approved_by_name: string | null;
  approved_at: string | null;
  rejection_note: string | null;
  document_file_path: string | null;
  document_original_name: string | null;
  document_uploaded_at: string | null;
  document_note: string | null;
  is_due_for_review: boolean;
  created_at: string;
  updated_at: string;
};

// ── Constants ────────────────────────────────────────────────────────────────

const ROLE_ADMIN = 1;
const ROLE_MANAGER = 2;
const MANAGEMENT_APPROVER_LABEL = "удирдлага";

const CATEGORIES = [
  "Мэдээллийн аюулгүй байдал",
  "Хандалтын удирдлага",
  "Эрсдэлийн менежмент",
  "Зөрчлийн хариу арга хэмжээ",
  "Нөөцлөлт ба сэргээлт",
  "Хөрөнгийн удирдлага",
  "Мониторинг ба илрүүлэлт",
  "Нийлүүлэлтийн сүлжээний аюулгүй байдал",
  "Хүний нөөцийн аюулгүй байдал",
  "Физик аюулгүй байдал",
  "Нийцлийн удирдлага",
  "Бусад",
];

const GOVERN_CATEGORIES = [
  "Эрсдэлийн менежмент",
  "Нийцлийн удирдлага",
  "Мэдээллийн аюулгүй байдал",
];

const FREQUENCIES = [
  { value: "Monthly", label: "Сар бүр" },
  { value: "Quarterly", label: "Улирал бүр" },
  { value: "Annually", label: "Жил бүр" },
];

const STATUS_MN: Record<string, string> = {
  Draft: "Ноорог",
  "Pending Approval": "Зөвшөөрөл хүлээж байна",
  Approved: "Батлагдсан",
  all: "Бүгд",
};

const FREQ_MN: Record<string, string> = {
  Monthly: "Сар бүр",
  Quarterly: "Улирал бүр",
  Annually: "Жил бүр",
};

const EMPTY_FORM = {
  title: "",
  description: "",
  category: CATEGORIES[0],
  review_frequency: "Quarterly",
  nist_ref: "",
  required_items: "",
  organization_response: "",
  csf_subcategory_ids: "",
  document_note: "",
};

const MAX_POLICY_PDF_SIZE = 20 * 1024 * 1024;

// ── Helpers ──────────────────────────────────────────────────────────────────

function compactMapping(policy: Policy) {
  const raw = policy.csf_subcategory_ids || policy.nist_ref || "";
  if (!raw) return "Дотоод";
  const ids = raw
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (ids.length <= 1) return ids[0] ?? raw;
  return `${ids[0]} +${ids.length - 1}`;
}

function reviewLabel(policy: Policy) {
  return policy.next_review_at
    ? formatPolicyDate(policy.next_review_at)
    : FREQ_MN[policy.review_frequency];
}

function formatPolicyDate(value: string | null) {
  if (!value) return "—";
  return new Date(value).toLocaleDateString("mn-MN", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function cleanPolicyDescription(value: string | null) {
  const cleaned = String(value ?? "")
    .replace(
      /\s*NIST CSF 2\.0\s+[A-Z]{2}\.[A-Z]{2}(?:-\d{2})?\s+шаардлаг(?:ын дагуу тогтоогдсон, мэдэгдсэн, хэрэгжүүлэгдсэн байх ёстой|а)\.?/g,
      "",
    )
    .replace(/\s{2,}/g, " ")
    .trim();

  return cleaned || "Тайлбар бүртгээгүй.";
}

function documentState(policy: Policy) {
  return policy.document_file_path
    ? {
        label: "Бодлого байна",
        cls: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300",
      }
    : {
        label: "Бодлого байхгүй",
        cls: "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-300",
      };
}

function approvalState(policy: Policy) {
  if (policy.status === "Approved" && policy.is_due_for_review) {
    return {
      label: "Хяналт хэтэрсэн",
      cls: "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900 dark:bg-orange-950/30 dark:text-orange-300",
    };
  }
  if (policy.status === "Approved") {
    return {
      label: "Батлагдсан",
      cls: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300",
    };
  }
  if (policy.status === "Pending Approval") {
    return {
      label: "Батлах хүлээгдэж байна",
      cls: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300",
    };
  }
  return {
    label: "Батлаагүй",
    cls: "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
  };
}

function tableStatus(policy: Policy) {
  if (!policy.document_file_path) {
    return {
      label: "Бодлого байхгүй",
      cls: "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-300",
    };
  }
  return approvalState(policy);
}

function requiresImplementationEvidence(policy: Policy) {
  return Boolean(policy.is_required || policy.nist_ref);
}

function requirementKey(value: string) {
  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

function parseRequirementItems(value: string | null | undefined) {
  return String(value ?? "")
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*(?:[-*•]|\d+[.)])\s+/, "").trim())
    .filter(Boolean);
}

function parseAddressedRequirementItems(value: string | null | undefined) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed
        .map((item) => String(item).trim())
        .filter((item) => item.length > 0);
    }
  } catch {
    // Older rows may use plain text; fall through to line parsing.
  }
  return parseRequirementItems(value);
}

function hasAllRequirementsAddressed(policy: Policy) {
  const requiredItems = parseRequirementItems(policy.required_items);
  if (requiredItems.length === 0) return false;

  const addressedKeys = new Set(
    parseAddressedRequirementItems(policy.addressed_requirement_items).map(
      requirementKey,
    ),
  );
  return requiredItems.every((item) => addressedKeys.has(requirementKey(item)));
}

function hasImplementationEvidence(policy: Policy) {
  return (
    Boolean(policy.organization_response?.trim()) ||
    hasAllRequirementsAddressed(policy)
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function PoliciesPage() {
  const { user } = useAuth();
  const router = useRouter();

  const role = Number((user as { role?: number | string } | null)?.role ?? 0);
  const userId = Number(
    (user as { user_id?: number | string } | null)?.user_id ?? 0,
  );
  const isAdmin = role === ROLE_ADMIN;
  const isManager = role === ROLE_MANAGER;
  // Segregation of duties: only Удирдлага (role 2) may approve.
  // Admins create/manage users & system — they do NOT approve policies.
  const canApprove = isManager;

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [requirementSavingKey, setRequirementSavingKey] = useState<
    string | null
  >(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [frameworkFilter, setFrameworkFilter] = useState("all");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [detailPolicy, setDetailPolicy] = useState<Policy | null>(null);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [documentFile, setDocumentFile] = useState<File | null>(null);
  const [formSaving, setFormSaving] = useState(false);
  const [formError, setFormError] = useState("");
  const [inlineUploading, setInlineUploading] = useState<Set<number>>(
    new Set(),
  );
  const [inlineUploadError, setInlineUploadError] = useState<
    Map<number, string>
  >(new Map());

  useEffect(() => {
    if (!user) router.push("/auth/login");
  }, [user, router]);

  // ── Data fetching ──────────────────────────────────────────────────────────

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/policies");
      if (res.ok) {
        const data = await res.json();
        setPolicies(data.policies ?? []);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user) {
      fetchPolicies();
    }
  }, [user]);

  // ── Derived stats ──────────────────────────────────────────────────────────

  const stats = useMemo(() => {
    const required = policies.filter((p) => p.is_required);
    const approved = policies.filter((p) => p.status === "Approved").length;
    const active = policies.filter(
      (p) => p.status === "Approved" && !p.is_due_for_review,
    ).length;
    const approvedRequired = required.filter(
      (p) => p.status === "Approved" && !p.is_due_for_review,
    ).length;
    const governMapped = policies.filter(
      (p) =>
        p.nist_ref?.startsWith("GV.") || GOVERN_CATEGORIES.includes(p.category),
    ).length;

    return {
      total: policies.length,
      approved,
      active,
      pending: policies.filter((p) => p.status === "Pending Approval").length,
      dueReview: policies.filter((p) => p.is_due_for_review).length,
      withDocuments: policies.filter((p) => p.document_file_path).length,
      required: required.length,
      approvedRequired,
      governMapped,
      compliancePct:
        required.length > 0
          ? Math.round((approvedRequired / required.length) * 100)
          : 0,
    };
  }, [policies]);

  const categoryOptions = useMemo(
    () => [
      "all",
      ...Array.from(new Set(policies.map((p) => p.category))).sort(),
    ],
    [policies],
  );

  const frameworkOptions = useMemo(
    () => [
      "all",
      ...Array.from(
        new Set(
          policies.map((p) =>
            p.nist_ref || p.csf_subcategory_ids
              ? "NIST CSF 2.0"
              : "Дотоод бодлого",
          ),
        ),
      ).sort(),
    ],
    [policies],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return policies.filter((p) => {
      if (statusFilter !== "all" && p.status !== statusFilter) return false;
      if (categoryFilter !== "all" && p.category !== categoryFilter)
        return false;
      if (frameworkFilter !== "all") {
        const framework =
          p.nist_ref || p.csf_subcategory_ids
            ? "NIST CSF 2.0"
            : "Дотоод бодлого";
        if (framework !== frameworkFilter) return false;
      }
      if (!q) return true;
      return [
        p.title,
        p.description,
        p.category,
        p.nist_ref,
        p.required_items,
        p.organization_response,
        p.addressed_requirement_items,
        p.csf_subcategory_ids,
        p.created_by_name,
        p.document_original_name,
        p.document_note,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [categoryFilter, frameworkFilter, policies, search, statusFilter]);

  const selectedPolicy = detailPolicy
    ? (policies.find((policy) => policy.id === detailPolicy.id) ?? detailPolicy)
    : null;

  // ── Dialog helpers ─────────────────────────────────────────────────────────

  const openAdd = () => {
    setEditingPolicy(null);
    setForm({ ...EMPTY_FORM });
    setDocumentFile(null);
    setFormError("");
    setDialogOpen(true);
  };

  const openEdit = (p: Policy) => {
    setEditingPolicy(p);
    setForm({
      title: p.title,
      description: p.description ?? "",
      category: p.category,
      review_frequency: p.review_frequency,
      nist_ref: p.nist_ref ?? "",
      required_items: p.required_items ?? "",
      organization_response: p.organization_response ?? "",
      csf_subcategory_ids: p.csf_subcategory_ids ?? p.nist_ref ?? "",
      document_note: p.document_note ?? "",
    });
    setDocumentFile(null);
    setFormError("");
    setDialogOpen(true);
  };

  const openDetails = (p: Policy) => {
    setDetailPolicy(p);
  };

  // ── API actions ────────────────────────────────────────────────────────────

  const handleDocumentFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] ?? null;
    setFormError("");

    if (!file) {
      setDocumentFile(null);
      return;
    }
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      setDocumentFile(null);
      e.target.value = "";
      setFormError("Зөвхөн PDF файл оруулна уу.");
      return;
    }
    if (file.size > MAX_POLICY_PDF_SIZE) {
      setDocumentFile(null);
      e.target.value = "";
      setFormError("PDF файл 20 MB-аас ихгүй байх ёстой.");
      return;
    }

    setDocumentFile(file);
  };

  const uploadPolicyDocument = async (policyId: number) => {
    if (!documentFile) return null;

    const fd = new FormData();
    fd.append("id", String(policyId));
    fd.append("file", documentFile);
    fd.append("document_note", form.document_note);

    const res = await fetch("/api/policies/document", {
      method: "POST",
      body: fd,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message);
    return data.policy as Policy;
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormSaving(true);
    setFormError("");
    try {
      let savedPolicy: Policy;

      if (editingPolicy) {
        const res = await fetch("/api/policies", {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: editingPolicy.id, ...form }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message);
        savedPolicy = data.policy;
      } else {
        const res = await fetch("/api/policies", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...form, created_by: userId }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message);
        savedPolicy = data.policy;
      }

      const uploadedPolicy = await uploadPolicyDocument(savedPolicy.id);
      const nextPolicy = uploadedPolicy ?? savedPolicy;

      setPolicies((prev) => {
        const exists = prev.some((p) => p.id === nextPolicy.id);
        if (exists) {
          return prev.map((p) =>
            p.id === nextPolicy.id ? { ...p, ...nextPolicy } : p,
          );
        }
        return [nextPolicy, ...prev];
      });
      setDocumentFile(null);
      setDialogOpen(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Алдаа гарлаа");
    } finally {
      setFormSaving(false);
    }
  };

  const submitForApproval = async (policy: Policy) => {
    if (!policy.document_file_path) {
      alert("Баталгаажуулахын өмнө PDF дүрэм журмаа оруулна уу.");
      return;
    }
    if (
      (policy.is_required || policy.nist_ref) &&
      !hasImplementationEvidence(policy)
    ) {
      alert("Заавал тусгах бүх зүйлсийг тэмдэглэнэ үү.");
      return;
    }

    setSavingId(policy.id);
    try {
      const res = await fetch("/api/policies", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: policy.id, submit: true }),
      });
      if (res.ok) await fetchPolicies();
    } finally {
      setSavingId(null);
    }
  };

  const approvePolicy = async (policy: Policy, approve: boolean) => {
    if (approve && !policy.document_file_path) {
      alert("PDF дүрэм журамгүй бүртгэлийг батлах боломжгүй.");
      return;
    }
    if (
      approve &&
      requiresImplementationEvidence(policy) &&
      !hasImplementationEvidence(policy)
    ) {
      alert("Заавал тусгах бүх зүйлсийг тэмдэглэнэ үү.");
      return;
    }

    setSavingId(policy.id);
    try {
      const res = await fetch("/api/policies", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: policy.id, approve, approved_by: userId }),
      });
      const data = (await res.json().catch(() => ({}))) as {
        message?: string;
      };
      if (!res.ok) {
        alert(data.message ?? "Бодлого батлах үед алдаа гарлаа.");
        return;
      }
      await fetchPolicies();
    } finally {
      setSavingId(null);
    }
  };

  const updateRequirementAddressed = async (
    policy: Policy,
    requirement: string,
    checked: boolean,
  ) => {
    const requiredItems = parseRequirementItems(policy.required_items);
    const currentKeys = new Set(
      parseAddressedRequirementItems(policy.addressed_requirement_items).map(
        requirementKey,
      ),
    );
    const nextKey = requirementKey(requirement);
    if (checked) {
      currentKeys.add(nextKey);
    } else {
      currentKeys.delete(nextKey);
    }
    const nextItems = requiredItems.filter((item) =>
      currentKeys.has(requirementKey(item)),
    );
    const savingKey = `${policy.id}:${nextKey}`;

    setRequirementSavingKey(savingKey);
    try {
      const res = await fetch("/api/policies", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: policy.id,
          addressed_requirement_items: nextItems,
        }),
      });
      const data = (await res.json().catch(() => ({}))) as {
        message?: string;
        policy?: Policy;
      };
      if (!res.ok || !data.policy) {
        alert(data.message ?? "Шаардлагын төлөв хадгалах үед алдаа гарлаа.");
        return;
      }
      setPolicies((prev) =>
        prev.map((item) =>
          item.id === policy.id ? { ...item, ...data.policy } : item,
        ),
      );
    } finally {
      setRequirementSavingKey(null);
    }
  };

  const resubmitForReview = async (policy: Policy) => {
    if (!policy.document_file_path) {
      alert("Шинэчлэлт илгээхийн өмнө PDF дүрэм журмаа оруулна уу.");
      return;
    }

    setSavingId(policy.id);
    try {
      const res = await fetch("/api/policies", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: policy.id, submit: true }),
      });
      if (res.ok) await fetchPolicies();
    } finally {
      setSavingId(null);
    }
  };

  const deletePolicy = async (policy: Policy): Promise<boolean> => {
    if (
      !window.confirm(`"${policy.title}" бодлогыг устгахдаа итгэлтэй байна уу?`)
    )
      return false;
    try {
      const res = await fetch(`/api/policies?id=${policy.id}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setPolicies((prev) => prev.filter((p) => p.id !== policy.id));
        return true;
      }
    } catch {
      alert("Устгаж чадсангүй");
    }
    return false;
  };

  const removePolicyDocument = async (policy: Policy) => {
    if (!window.confirm(`"${policy.title}" PDF баримтыг устгах уу?`)) return;

    setSavingId(policy.id);
    try {
      const res = await fetch(`/api/policies/document?id=${policy.id}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      setPolicies((prev) =>
        prev.map((p) => (p.id === policy.id ? { ...p, ...data.policy } : p)),
      );
    } catch (err) {
      alert(err instanceof Error ? err.message : "PDF устгаж чадсангүй");
    } finally {
      setSavingId(null);
    }
  };

  const handleInlineUpload = async (policy: Policy, file: File) => {
    setInlineUploadError((prev) => {
      const m = new Map(prev);
      m.delete(policy.id);
      return m;
    });

    if (!file.name.toLowerCase().endsWith(".pdf")) {
      setInlineUploadError((prev) =>
        new Map(prev).set(policy.id, "Зөвхөн PDF файл оруулна уу."),
      );
      return;
    }
    if (file.size > MAX_POLICY_PDF_SIZE) {
      setInlineUploadError((prev) =>
        new Map(prev).set(policy.id, "PDF файл 20 MB-аас ихгүй байх ёстой."),
      );
      return;
    }

    setInlineUploading((prev) => new Set(prev).add(policy.id));
    try {
      const fd = new FormData();
      fd.append("id", String(policy.id));
      fd.append("file", file);
      const res = await fetch("/api/policies/document", {
        method: "POST",
        body: fd,
      });
      const data = await res.json();
      if (!res.ok)
        throw new Error(data.message ?? "PDF оруулах үед алдаа гарлаа");
      setPolicies((prev) =>
        prev.map((p) => (p.id === policy.id ? { ...p, ...data.policy } : p)),
      );
    } catch (err) {
      setInlineUploadError((prev) =>
        new Map(prev).set(
          policy.id,
          err instanceof Error ? err.message : "PDF оруулах үед алдаа гарлаа",
        ),
      );
    } finally {
      setInlineUploading((prev) => {
        const s = new Set(prev);
        s.delete(policy.id);
        return s;
      });
    }
  };

  if (!user) return null;

  const detailCanEdit =
    selectedPolicy &&
    (isAdmin || selectedPolicy.created_by === userId) &&
    selectedPolicy.status !== "Pending Approval";

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="app-page overflow-x-hidden p-4 pb-8 sm:p-6 md:p-8">
      <div className="mx-auto max-w-360 space-y-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-normal text-slate-950 dark:text-slate-50">
              Дүрэм журам
            </h1>
          </div>
          <div className="flex w-full flex-col gap-2 sm:flex-row lg:w-auto">
            <div className="relative sm:w-80">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Дүрэм журам хайх..."
                className="h-10 bg-white pl-10 shadow-sm dark:bg-slate-950"
              />
            </div>
            <Button
              variant="outline"
              onClick={fetchPolicies}
              disabled={loading}
              className="h-10 gap-2 bg-white shadow-sm dark:bg-slate-950"
            >
              <RefreshCw
                className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
              />
              Шинэчлэх
            </Button>
            <Button
              onClick={openAdd}
              className="h-10 gap-2 bg-blue-600 shadow-sm hover:bg-blue-700"
            >
              <Plus className="h-4 w-4" />
              Журам нэмэх
            </Button>
          </div>
        </div>

        <div className="space-y-5">
          <div className="min-w-0 space-y-5">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {[
                {
                  label: "Нийт",
                  value: stats.total,
                  sub: "Бүртгэлтэй баримт бичиг",
                  icon: ClipboardList,
                  color: "text-blue-700",
                  tone: "bg-blue-50 text-blue-700 ring-blue-100 dark:bg-blue-950/40 dark:text-blue-300 dark:ring-blue-900",
                },
                {
                  label: "Идэвхтэй",
                  value: stats.active,
                  sub: "Одоогоор мөрдөгдөж буй",
                  icon: CheckCircle2,
                  color: "text-emerald-700",
                  tone: "bg-emerald-50 text-emerald-700 ring-emerald-100 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-900",
                },
                {
                  label: "Хүлээгдэж буй",
                  value: stats.pending,
                  sub: "Зөвшөөрөл хүлээж буй",
                  icon: Clock,
                  color: "text-orange-700",
                  tone: "bg-orange-50 text-orange-700 ring-orange-100 dark:bg-orange-950/40 dark:text-orange-300 dark:ring-orange-900",
                },
                {
                  label: "Хэтэрсэн",
                  value: stats.dueReview,
                  sub: "Дахин хянах шаардлагатай",
                  icon: AlertTriangle,
                  color: "text-rose-700",
                  tone: "bg-rose-50 text-rose-700 ring-rose-100 dark:bg-rose-950/40 dark:text-rose-300 dark:ring-rose-900",
                },
              ].map(({ label, value, sub, icon: Icon, color, tone }) => (
                <div
                  key={label}
                  className="rounded-lg border border-slate-200 bg-white px-4 py-3 shadow-sm dark:border-slate-800 dark:bg-slate-950"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-3">
                      <span
                        className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-md ring-1 ${tone}`}
                      >
                        <Icon className="h-4 w-4" />
                      </span>
                      <div className="min-w-0">
                        <div className="truncate text-sm font-semibold text-slate-950 dark:text-slate-50">
                          {label}
                        </div>
                        <div className="mt-0.5 truncate text-xs text-muted-foreground">
                          {sub}
                        </div>
                      </div>
                    </div>
                    <span
                      className={`shrink-0 text-2xl font-bold tabular-nums ${color}`}
                    >
                      {value}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {stats.dueReview > 0 && (
              <div className="flex items-start gap-3 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-rose-700 shadow-sm dark:border-rose-900/70 dark:bg-rose-950/30 dark:text-rose-300">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <p className="text-sm">
                  <span className="font-semibold">
                    {stats.dueReview} дүрэм журам
                  </span>{" "}
                  хяналтын хугацаа хэтэрсэн байна. Шинэчилж дахин баталгаажуулна
                  уу.
                </p>
              </div>
            )}

            <section className="min-w-0 overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="space-y-4 border-b border-slate-200 p-4 dark:border-slate-800">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <h2 className="text-base font-bold text-slate-950 dark:text-slate-50">
                      Бодлогын хүснэгт
                    </h2>
                  </div>
                  <span className="rounded-full bg-slate-100 px-3 py-1 text-sm font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                    Нийт {filtered.length} дүрэм
                  </span>
                </div>

                <div className="grid gap-3 md:grid-cols-[1fr_1fr_1fr_1.4fr_auto]">
                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    className="h-10 rounded-md border border-slate-200 bg-white px-3 text-sm shadow-sm outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-800 dark:bg-slate-950 dark:focus:ring-blue-950"
                  >
                    {categoryOptions.map((category) => (
                      <option key={category} value={category}>
                        {category === "all" ? "Бүх ангилал" : category}
                      </option>
                    ))}
                  </select>
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="h-10 rounded-md border border-slate-200 bg-white px-3 text-sm shadow-sm outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-800 dark:bg-slate-950 dark:focus:ring-blue-950"
                  >
                    {["all", "Draft", "Pending Approval", "Approved"].map(
                      (status) => (
                        <option key={status} value={status}>
                          {STATUS_MN[status] ?? status}
                        </option>
                      ),
                    )}
                  </select>
                  <select
                    value={frameworkFilter}
                    onChange={(e) => setFrameworkFilter(e.target.value)}
                    className="h-10 rounded-md border border-slate-200 bg-white px-3 text-sm shadow-sm outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-800 dark:bg-slate-950 dark:focus:ring-blue-950"
                  >
                    {frameworkOptions.map((framework) => (
                      <option key={framework} value={framework}>
                        {framework === "all" ? "Бүх хүрээ" : framework}
                      </option>
                    ))}
                  </select>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                    <Input
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Хүснэгтээс хайх..."
                      className="h-10 bg-slate-50 pl-10 shadow-sm dark:bg-slate-900"
                    />
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    className="h-10 gap-2 bg-white shadow-sm dark:bg-slate-950"
                    onClick={() => {
                      setSearch("");
                      setStatusFilter("all");
                      setCategoryFilter("all");
                      setFrameworkFilter("all");
                    }}
                  >
                    <X className="h-4 w-4" />
                    Цэвэрлэх
                  </Button>
                </div>
              </div>

              <div className="w-full">
                <table className="w-full border-collapse text-sm">
                  <thead className="border-b border-slate-200 text-left text-xs font-semibold text-slate-700 dark:border-slate-800 dark:text-slate-300">
                    <tr>
                      <th className="w-52 whitespace-nowrap px-3 py-3">
                        Бодлогын нэр
                      </th>
                      <th className="w-34 whitespace-nowrap px-3 py-3">
                        Ангилал
                      </th>
                      <th className="w-24 whitespace-nowrap px-3 py-3">
                        Холбоо
                      </th>
                      <th className="w-28 whitespace-nowrap px-3 py-3">
                        Хариуцагч
                      </th>
                      <th className="w-32 whitespace-nowrap px-3 py-3">
                        Статус
                      </th>
                      <th className="w-26 whitespace-nowrap px-3 py-3">
                        Хяналт
                      </th>
                      <th className="w-24 whitespace-nowrap px-3 py-3">
                        Хавсралт
                      </th>
                      <th className="w-20 whitespace-nowrap px-3 py-3">
                        Үйлдэл
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      <tr>
                        <td
                          colSpan={8}
                          className="px-4 py-12 text-center text-muted-foreground"
                        >
                          Дүрэм журам ачааллаж байна...
                        </td>
                      </tr>
                    ) : filtered.length === 0 ? (
                      <tr>
                        <td
                          colSpan={8}
                          className="px-4 py-12 text-center text-muted-foreground"
                        >
                          Дүрэм журам олдсонгүй.
                        </td>
                      </tr>
                    ) : (
                      filtered.map((policy) => {
                        const isOwner = policy.created_by === userId;
                        const canEdit = isAdmin || isOwner;
                        const canUploadDocument =
                          policy.status !== "Pending Approval" &&
                          (canEdit || !policy.document_file_path);
                        const status = tableStatus(policy);
                        const selected = selectedPolicy?.id === policy.id;

                        return (
                          <tr
                            key={policy.id}
                            role="button"
                            tabIndex={0}
                            onClick={() => openDetails(policy)}
                            onKeyDown={(event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                event.preventDefault();
                                openDetails(policy);
                              }
                            }}
                            className={`cursor-pointer border-b border-slate-100 align-top dark:border-slate-800 ${
                              selected
                                ? "bg-blue-50/80 dark:bg-blue-950/20"
                                : "bg-white dark:bg-slate-950"
                            }`}
                          >
                            <td className="px-3 py-3">
                              <span className="block max-w-48 whitespace-normal font-medium leading-5 text-slate-950 dark:text-slate-50">
                                {policy.title}
                              </span>
                              {policy.is_required && (
                                <span className="mt-1 inline-flex rounded-full bg-violet-50 px-2 py-0.5 text-[11px] font-semibold text-violet-700 ring-1 ring-violet-100 dark:bg-violet-950/40 dark:text-violet-300 dark:ring-violet-900">
                                  Заавал
                                </span>
                              )}
                            </td>
                            <td className="px-3 py-3 text-slate-700 dark:text-slate-200">
                              {policy.category}
                            </td>
                            <td className="px-3 py-3">
                              <span className="font-medium text-slate-900 dark:text-slate-50">
                                {compactMapping(policy)}
                              </span>
                            </td>
                            <td className="px-3 py-3 text-slate-800 dark:text-slate-100">
                              {policy.created_by_name ?? "-"}
                            </td>
                            <td className="px-3 py-3">
                              <span
                                className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${status.cls}`}
                              >
                                {status.label}
                              </span>
                              {inlineUploadError.get(policy.id) && (
                                <p className="mt-1 text-[11px] font-medium text-rose-600 dark:text-rose-400">
                                  {inlineUploadError.get(policy.id)}
                                </p>
                              )}
                            </td>
                            <td className="px-3 py-3 text-slate-800 dark:text-slate-100">
                              {reviewLabel(policy)}
                            </td>
                            <td className="px-3 py-3">
                              {canUploadDocument ? (
                                <label
                                  className={`inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md border border-blue-200 bg-blue-50 px-3 text-xs font-semibold text-blue-700 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-300 ${
                                    inlineUploading.has(policy.id)
                                      ? "pointer-events-none opacity-60"
                                      : ""
                                  }`}
                                  onClick={(event) => event.stopPropagation()}
                                >
                                  <UploadCloud className="h-3.5 w-3.5" />
                                  {inlineUploading.has(policy.id)
                                    ? "Uploading..."
                                    : "Upload"}
                                  <input
                                    type="file"
                                    accept=".pdf,application/pdf"
                                    className="sr-only"
                                    disabled={inlineUploading.has(policy.id)}
                                    onChange={(event) => {
                                      const file = event.target.files?.[0];
                                      if (file)
                                        handleInlineUpload(policy, file);
                                      event.target.value = "";
                                    }}
                                  />
                                </label>
                              ) : (
                                <span className="text-xs font-medium text-slate-400">
                                  —
                                </span>
                              )}
                            </td>
                            <td className="px-3 py-3">
                              {canApprove && policy.status !== "Approved" ? (
                                policy.created_by === userId ? (
                                  <span
                                    title="Өөрийн бодлогыг батлах боломжгүй"
                                    className="inline-flex h-8 items-center gap-1.5 rounded-md border border-amber-200 bg-amber-50 px-2 text-[11px] font-medium text-amber-600 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-400"
                                  >
                                    Хязгаарлагдсан
                                  </span>
                                ) : (
                                  <button
                                    type="button"
                                    disabled={savingId === policy.id}
                                    onClick={(event) => {
                                      event.stopPropagation();
                                      approvePolicy(policy, true);
                                    }}
                                    className="inline-flex h-8 items-center gap-1.5 rounded-md border border-emerald-200 bg-emerald-50 px-3 text-xs font-semibold text-emerald-700 transition hover:bg-emerald-100 disabled:pointer-events-none disabled:opacity-60 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300 dark:hover:bg-emerald-950/70"
                                  >
                                    <CheckCircle2 className="h-3.5 w-3.5" />
                                    Батлах
                                  </button>
                                )
                              ) : (
                                <span className="text-xs font-medium text-slate-400">
                                  —
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              <div className="flex flex-col gap-3 border-t border-slate-200 px-3 py-3 text-sm text-muted-foreground dark:border-slate-800 sm:flex-row sm:items-center sm:justify-between">
                <span>
                  {stats.total > 0
                    ? `Нийт ${stats.total} дүрмээс ${filtered.length} харагдаж байна`
                    : "Одоогоор дүрэм журам бүртгэгдээгүй байна"}
                </span>
                <div className="flex items-center gap-2">
                  <button className="h-8 rounded-md border border-slate-200 px-3 text-slate-400 dark:border-slate-800">
                    1
                  </button>
                </div>
              </div>
            </section>
          </div>
        </div>

        {/* ── Selected policy details ──────────────────────────────────────── */}
        <Dialog
          open={Boolean(selectedPolicy)}
          onOpenChange={(open) => {
            if (!open) setDetailPolicy(null);
          }}
        >
          {selectedPolicy && (
            <DialogContent className="max-w-4xl">
              <DialogHeader>
                <DialogTitle className="flex items-start gap-3">
                  <BookOpen className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />
                  <span>
                    <span className="block text-left leading-6">
                      {selectedPolicy.title}
                    </span>
                    <span className="mt-2 flex flex-wrap gap-1.5">
                      {selectedPolicy.is_required && (
                        <span className="rounded-full bg-violet-50 px-2 py-0.5 text-[11px] font-semibold text-violet-700 ring-1 ring-violet-100 dark:bg-violet-950/40 dark:text-violet-300 dark:ring-violet-900">
                          Заавал
                        </span>
                      )}
                      <span
                        className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${approvalState(selectedPolicy).cls}`}
                      >
                        {approvalState(selectedPolicy).label}
                      </span>
                      <span
                        className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${documentState(selectedPolicy).cls}`}
                      >
                        {documentState(selectedPolicy).label}
                      </span>
                    </span>
                  </span>
                </DialogTitle>
              </DialogHeader>

              <div className="max-h-[65vh] space-y-4 overflow-y-auto pr-1">
                <div className="grid gap-3 md:grid-cols-3">
                  <DetailField
                    label="Ангилал"
                    value={selectedPolicy.category}
                  />
                  <DetailField
                    label="Хариуцагч"
                    value={selectedPolicy.created_by_name ?? "Томилоогүй"}
                  />
                  <DetailField
                    label="Хяналт"
                    value={reviewLabel(selectedPolicy)}
                  />
                  <DetailField
                    label="Холбоо"
                    value={compactMapping(selectedPolicy)}
                  />
                  <DetailField
                    label="Баталсан"
                    value={
                      selectedPolicy.approved_at
                        ? MANAGEMENT_APPROVER_LABEL
                        : "—"
                    }
                  />
                  <DetailField
                    label="Дараагийн хяналт"
                    value={formatPolicyDate(selectedPolicy.next_review_at)}
                  />
                </div>

                <div className="grid gap-3">
                  <DetailText
                    title="Тайлбар"
                    value={cleanPolicyDescription(selectedPolicy.description)}
                  />
                  <RequirementChecklist
                    policy={selectedPolicy}
                    savingKey={requirementSavingKey}
                    onToggle={updateRequirementAddressed}
                  />
                </div>
              </div>

              <DialogFooter className="gap-3 sm:justify-between">
                <div className="flex flex-wrap items-center gap-2">
                  {selectedPolicy.document_file_path && (
                    <>
                      <a
                        href={selectedPolicy.document_file_path}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex h-9 items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-700 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        Харах
                      </a>
                      <a
                        href={selectedPolicy.document_file_path}
                        download
                        className="inline-flex h-9 items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-700 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
                      >
                        <Download className="h-3.5 w-3.5" />
                        Татах
                      </a>
                      {detailCanEdit && (
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => removePolicyDocument(selectedPolicy)}
                          className="h-9 border-rose-200 text-rose-600"
                        >
                          <X className="h-4 w-4" />
                          PDF устгах
                        </Button>
                      )}
                    </>
                  )}
                </div>

                <div className="flex flex-wrap items-center justify-end gap-2">
                  {canApprove && selectedPolicy.status !== "Approved" && (
                    <>
                      {selectedPolicy.status === "Pending Approval" && (
                        <Button
                          type="button"
                          variant="outline"
                          disabled={savingId === selectedPolicy.id}
                          onClick={() => approvePolicy(selectedPolicy, false)}
                          className="h-9 border-rose-200 text-rose-600"
                        >
                          Буцаах
                        </Button>
                      )}
                      {selectedPolicy.created_by === userId ? (
                        <span className="inline-flex items-center gap-1.5 rounded-md border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300">
                          Өөрийн бодлогыг батлах боломжгүй
                        </span>
                      ) : (
                        <Button
                          type="button"
                          disabled={savingId === selectedPolicy.id}
                          onClick={() => approvePolicy(selectedPolicy, true)}
                          className="h-9 bg-emerald-600 hover:bg-emerald-700"
                        >
                          Батлах
                        </Button>
                      )}
                    </>
                  )}
                  {detailCanEdit && selectedPolicy.status === "Draft" && (
                    <Button
                      type="button"
                      variant="outline"
                      disabled={savingId === selectedPolicy.id}
                      onClick={() => submitForApproval(selectedPolicy)}
                      className="h-9"
                    >
                      Илгээх
                    </Button>
                  )}
                  {detailCanEdit &&
                    selectedPolicy.status === "Approved" &&
                    selectedPolicy.is_due_for_review && (
                      <Button
                        type="button"
                        variant="outline"
                        disabled={savingId === selectedPolicy.id}
                        onClick={() => resubmitForReview(selectedPolicy)}
                        className="h-9 border-orange-200 text-orange-700"
                      >
                        Дахин илгээх
                      </Button>
                    )}
                  {detailCanEdit && (
                    <Button
                      type="button"
                      onClick={() => {
                        const policy = selectedPolicy;
                        setDetailPolicy(null);
                        openEdit(policy);
                      }}
                      className="h-9 bg-blue-600 hover:bg-blue-700"
                    >
                      <Edit3 className="h-4 w-4" />
                      Засах
                    </Button>
                  )}
                  {isAdmin && (
                    <Button
                      type="button"
                      variant="outline"
                      onClick={async () => {
                        const deleted = await deletePolicy(selectedPolicy);
                        if (deleted) setDetailPolicy(null);
                      }}
                      className="h-9 border-rose-200 text-rose-600"
                    >
                      Устгах
                    </Button>
                  )}
                </div>
              </DialogFooter>
            </DialogContent>
          )}
        </Dialog>

        {/* ── Add / Edit dialog ─────────────────────────────────────────────── */}
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent className="max-w-2xl flex flex-col max-h-[calc(100vh-4rem)]">
            <DialogHeader className="shrink-0">
              <DialogTitle className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-blue-600" />
                {editingPolicy ? "Дүрэм журам засах" : "Шинэ дүрэм журам нэмэх"}
              </DialogTitle>
              <DialogDescription className="sr-only">
                Дүрэм журмын гарчиг, тайлбар, ангилал болон хяналтын давтамжийг
                бүртгэнэ.
              </DialogDescription>
            </DialogHeader>

            <form
              id="policy-edit-form"
              onSubmit={handleFormSubmit}
              className="space-y-4 pt-2 overflow-y-auto min-h-0 flex-1 pr-1"
            >
              {/* Title */}
              <div>
                <Label htmlFor="pol-title" className="mb-1.5 block">
                  Гарчиг <span className="text-red-500">*</span>
                </Label>
                <Input
                  id="pol-title"
                  value={form.title}
                  onChange={(e) =>
                    setForm((p) => ({ ...p, title: e.target.value }))
                  }
                  placeholder="жишээ: Мэдээллийн аюулгүй байдлын бодлого"
                  required
                />
              </div>

              {/* Description */}
              <div>
                <Label htmlFor="pol-desc" className="mb-1.5 block">
                  Тайлбар
                </Label>
                <textarea
                  id="pol-desc"
                  value={form.description}
                  onChange={(e) =>
                    setForm((p) => ({ ...p, description: e.target.value }))
                  }
                  placeholder="Дүрэм журмын зорилго, хамрах хүрээг товч тайлбарлана уу..."
                  rows={6}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 resize-none"
                />
              </div>

              {/* Requirement fields */}
              <div className="rounded-lg border border-blue-100 bg-blue-50 p-3 dark:border-blue-900 dark:bg-blue-950/20">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-blue-800 dark:text-blue-300">
                  <ClipboardList className="h-4 w-4" />
                  Шаардлагатай зүйлс ба хэрэгжилт
                </div>

                <div className="grid gap-3">
                  <div>
                    <Label
                      htmlFor="pol-required-items"
                      className="mb-1.5 block"
                    >
                      Дүрэм журам дээр заавал тусгах зүйлс
                    </Label>
                    <textarea
                      id="pol-required-items"
                      value={form.required_items}
                      onChange={(e) =>
                        setForm((p) => ({
                          ...p,
                          required_items: e.target.value,
                        }))
                      }
                      placeholder="- Хамрах хүрээ&#10;- Хариуцагч&#10;- Review давтамж"
                      rows={10}
                      className="w-full rounded-md border border-input bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 resize-none dark:bg-slate-950"
                    />
                  </div>
                  <div>
                    <Label htmlFor="pol-org-response" className="mb-1.5 block">
                      Байгууллагын тайлбар / хэрэгжилт
                    </Label>
                    <textarea
                      id="pol-org-response"
                      value={form.organization_response}
                      onChange={(e) =>
                        setForm((p) => ({
                          ...p,
                          organization_response: e.target.value,
                        }))
                      }
                      placeholder="Одоогоор мөрдөж буй журам, хамрах хүрээ, эзэмшигч, сайжруулах зүйлс..."
                      rows={7}
                      className="w-full rounded-md border border-input bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40 resize-none dark:bg-slate-950"
                    />
                  </div>
                </div>
              </div>

              {/* PDF document */}
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-900/60">
                <div className="mb-3 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    <FileUp className="h-4 w-4 text-cyan-600" />
                    Аюулгүй байдлын дүрэм журмын PDF
                  </div>
                  {editingPolicy?.document_file_path && (
                    <a
                      href={editingPolicy.document_file_path}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-700 hover:underline dark:text-cyan-300"
                    >
                      <Download className="h-3.5 w-3.5" />
                      Одоогийн PDF
                    </a>
                  )}
                </div>

                <div className="grid gap-3 md:grid-cols-[1fr_220px]">
                  <div>
                    <Label htmlFor="pol-doc-note" className="mb-1.5 block">
                      PDF тайлбар
                    </Label>
                    <textarea
                      id="pol-doc-note"
                      value={form.document_note}
                      onChange={(e) =>
                        setForm((p) => ({
                          ...p,
                          document_note: e.target.value,
                        }))
                      }
                      placeholder="Жишээ: Ажилтны дагаж мөрдөх үндсэн аюулгүй байдлын журам"
                      rows={3}
                      className="w-full rounded-md border border-input bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/40 resize-none dark:bg-slate-950"
                    />
                  </div>

                  <div>
                    <Label className="mb-1.5 block">PDF файл</Label>
                    <label className="flex h-23 cursor-pointer flex-col items-center justify-center gap-2 rounded-md border border-dashed border-cyan-300 bg-white px-3 text-center text-xs font-medium text-cyan-700 transition-colors hover:bg-cyan-50 dark:border-cyan-900 dark:bg-slate-950 dark:text-cyan-300 dark:hover:bg-cyan-950/30">
                      <UploadCloud className="h-5 w-5" />
                      <span className="max-w-full truncate">
                        {documentFile ? documentFile.name : "PDF сонгох"}
                      </span>
                      <input
                        key={documentFile ? documentFile.name : "empty"}
                        type="file"
                        accept=".pdf,application/pdf"
                        className="sr-only"
                        onChange={handleDocumentFileChange}
                      />
                    </label>
                    {documentFile && (
                      <button
                        type="button"
                        onClick={() => setDocumentFile(null)}
                        className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-rose-600"
                      >
                        <X className="h-3.5 w-3.5" />
                        Сонголт цэвэрлэх
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Category + Frequency */}
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <Label htmlFor="pol-cat" className="mb-1.5 block">
                    Ангилал
                  </Label>
                  <select
                    id="pol-cat"
                    value={form.category}
                    onChange={(e) =>
                      setForm((p) => ({ ...p, category: e.target.value }))
                    }
                    className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                  >
                    {CATEGORIES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label htmlFor="pol-freq" className="mb-1.5 block">
                    Хяналтын давтамж
                  </Label>
                  <select
                    id="pol-freq"
                    value={form.review_frequency}
                    onChange={(e) =>
                      setForm((p) => ({
                        ...p,
                        review_frequency: e.target.value,
                      }))
                    }
                    className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                  >
                    {FREQUENCIES.map((f) => (
                      <option key={f.value} value={f.value}>
                        {f.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Info note */}
              <div className="rounded-lg bg-blue-50 dark:bg-blue-950/30 border border-blue-100 dark:border-blue-900 px-3 py-2.5 text-xs text-blue-700 dark:text-blue-400">
                Хадгалсны дараа <strong>Баталгаажуулах</strong> товчоор
                удирдлагад илгээнэ үү. Удирдлага батласны дараа хяналтын хуваарь
                автоматаар тогтоогдоно.
              </div>

              {formError && (
                <div className="rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 px-3 py-2 text-sm text-red-700 dark:text-red-400">
                  {formError}
                </div>
              )}
            </form>

            <DialogFooter className="shrink-0 pt-2 gap-2 border-t border-border mt-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setDialogOpen(false)}
              >
                Болих
              </Button>
              <Button
                type="submit"
                form="policy-edit-form"
                disabled={formSaving}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {formSaving
                  ? "Хадгалж байна..."
                  : editingPolicy
                    ? "Өөрчлөлт хадгалах"
                    : "Дүрэм нэмэх"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}

function DetailField({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-900/60">
      <p className="text-[11px] font-semibold uppercase text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 text-sm font-medium text-slate-950 dark:text-slate-50">
        {value}
      </p>
      {sub && <p className="mt-1 text-xs text-muted-foreground">{sub}</p>}
    </div>
  );
}

function DetailText({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
      <h4 className="text-sm font-semibold text-slate-950 dark:text-slate-50">
        {title}
      </h4>
      <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-muted-foreground">
        {value}
      </p>
    </div>
  );
}

function RequirementChecklist({
  policy,
  savingKey,
  onToggle,
}: {
  policy: Policy;
  savingKey: string | null;
  onToggle: (policy: Policy, requirement: string, checked: boolean) => void;
}) {
  const requirements = parseRequirementItems(policy.required_items);
  const addressedKeys = new Set(
    parseAddressedRequirementItems(policy.addressed_requirement_items).map(
      requirementKey,
    ),
  );
  const addressedCount = requirements.filter((item) =>
    addressedKeys.has(requirementKey(item)),
  ).length;

  if (requirements.length === 0) {
    return <DetailText title="Заавал тусгах зүйлс" value="Бүртгээгүй." />;
  }

  return (
    <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-950 dark:text-slate-50">
          Заавал тусгах зүйлс
        </h4>
        <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600 dark:bg-slate-900 dark:text-slate-300">
          {addressedCount}/{requirements.length} биелсэн
        </span>
      </div>
      <div className="mt-3 space-y-2">
        {requirements.map((requirement, index) => {
          const key = requirementKey(requirement);
          const isChecked = addressedKeys.has(key);
          const isSaving = savingKey === `${policy.id}:${key}`;

          return (
            <label
              key={`${index}-${key}`}
              className={`flex cursor-pointer select-none items-start gap-3 rounded-md border px-3 py-2 text-sm leading-6 transition ${
                isChecked
                  ? "border-emerald-200 bg-emerald-50 text-slate-950 dark:border-emerald-900/70 dark:bg-emerald-950/20 dark:text-slate-50"
                  : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300 dark:hover:bg-slate-900/60"
              } ${savingKey && !isSaving ? "opacity-70" : ""}`}
            >
              <input
                type="checkbox"
                checked={isChecked}
                disabled={Boolean(savingKey)}
                onChange={(event) =>
                  onToggle(policy, requirement, event.target.checked)
                }
                className="mt-1 h-4 w-4 shrink-0 rounded border-slate-300 text-emerald-600 focus:ring-emerald-500 disabled:opacity-60"
              />
              <span className="pointer-events-none">{requirement}</span>
              {isSaving && (
                <span className="ml-auto shrink-0 text-xs font-semibold text-emerald-700 dark:text-emerald-300">
                  Хадгалж байна...
                </span>
              )}
            </label>
          );
        })}
      </div>
    </div>
  );
}
