"use client";

import { useAuth } from "@/app/context/AuthContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
  Edit3,
  Mail,
  Plus,
  RefreshCw,
  Shield,
  Trash2,
  User,
  Users,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

interface AppUser {
  id: number;
  full_name: string;
  email: string;
  role_id: number;
  status: string;
  created_at: string;
  updated_at: string;
}

const ROLE_LABELS: Record<number, string> = {
  1: "Админ",
  2: "Удирдлага",
  3: "Хэрэглэгч",
};

const ROLE_STYLE: Record<number, string> = {
  1: "bg-purple-100 text-purple-700 dark:bg-purple-950/50 dark:text-purple-300 border-purple-200 dark:border-purple-900",
  2: "bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300 border-amber-200 dark:border-amber-900",
  3: "bg-blue-100 text-blue-700 dark:bg-blue-950/50 dark:text-blue-300 border-blue-200 dark:border-blue-900",
};

const STATUS_LABELS: Record<string, string> = {
  active: "Идэвхтэй",
  inactive: "Идэвхгүй",
  suspended: "Түдгэлзүүлсэн",
};

const STATUS_STYLE: Record<string, string> = {
  active:
    "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300 border-emerald-200 dark:border-emerald-900",
  inactive:
    "bg-slate-100 text-slate-600 dark:bg-slate-800/50 dark:text-slate-400 border-slate-200 dark:border-slate-700",
  suspended:
    "bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300 border-red-200 dark:border-red-900",
};

const EMPTY_FORM = {
  full_name: "",
  email: "",
  password: "",
  role_id: 3,
  status: "active",
};

export default function UsersPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [users, setUsers] = useState<AppUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [search, setSearch] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<AppUser | null>(null);
  const [formData, setFormData] = useState({ ...EMPTY_FORM });
  const [formError, setFormError] = useState("");

  useEffect(() => {
    if (!user) router.push("/auth/login");
  }, [user, router]);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/users");
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user) fetchUsers();
  }, [user]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return users;
    return users.filter(
      (u) =>
        u.full_name.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q),
    );
  }, [users, search]);

  const stats = useMemo(
    () => ({
      total: users.length,
      managers: users.filter((u) => u.role_id === 2).length,
      active: users.filter((u) => u.status === "active").length,
    }),
    [users],
  );

  const openAdd = () => {
    setEditingUser(null);
    setFormData({ ...EMPTY_FORM });
    setFormError("");
    setDialogOpen(true);
  };

  const openEdit = (u: AppUser) => {
    setEditingUser(u);
    setFormData({
      full_name: u.full_name,
      email: u.email,
      password: "",
      role_id: u.role_id,
      status: u.status,
    });
    setFormError("");
    setDialogOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setFormError("");
    try {
      if (editingUser) {
        const res = await fetch("/api/users", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: editingUser.id, ...formData }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message);
        setUsers((prev) =>
          prev.map((u) => (u.id === editingUser.id ? data.user : u)),
        );
      } else {
        const res = await fetch("/api/users", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(formData),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message);
        setUsers((prev) => [data.user, ...prev]);
      }
      setDialogOpen(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Алдаа гарлаа");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (u: AppUser) => {
    if (
      !window.confirm(
        `"${u.full_name}" хэрэглэгчийг устгахдаа итгэлтэй байна уу?`,
      )
    )
      return;
    try {
      const res = await fetch(`/api/users?id=${u.id}`, { method: "DELETE" });
      if (res.ok) {
        setUsers((prev) => prev.filter((x) => x.id !== u.id));
      }
    } catch {
      alert("Устгаж чадсангүй");
    }
  };

  if (!user) return null;

  return (
    <div className="space-y-6 p-4 sm:p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Users className="w-7 h-7 text-blue-600" />
            Хэрэглэгчийн удирдлага
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Системийн хэрэглэгчид болон эрхийг удирдах
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchUsers}
            disabled={loading}
            className="gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Шинэчлэх
          </Button>
          <Button
            onClick={openAdd}
            className="gap-1.5 bg-blue-600 hover:bg-blue-700"
          >
            <Plus className="w-4 h-4" />
            Хэрэглэгч нэмэх
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          {
            label: "Нийт хэрэглэгч",
            value: stats.total,
            icon: Users,
            color: "text-blue-600",
          },
          {
            label: "Идэвхтэй",
            value: stats.active,
            icon: User,
            color: "text-emerald-600",
          },
          {
            label: "Удирдлага",
            value: stats.managers,
            icon: Shield,
            color: "text-amber-600",
          },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="shadow-none">
            <CardContent className="p-4 flex items-center gap-3">
              <Icon className={`w-5 h-5 ${color}`} />
              <div>
                <p className={`text-2xl font-black ${color}`}>{value}</p>
                <p className="text-xs text-muted-foreground font-medium">
                  {label}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Нэр эсвэл имэйлээр хайх..."
          className="pl-9"
        />
      </div>

      {/* Table */}
      <Card className="shadow-none overflow-hidden">
        {loading ? (
          <CardContent className="p-8 text-center text-muted-foreground">
            Хэрэглэгчид ачааллаж байна...
          </CardContent>
        ) : filtered.length === 0 ? (
          <CardContent className="p-8 text-center text-muted-foreground">
            Хэрэглэгч олдсонгүй.
          </CardContent>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-xs text-muted-foreground uppercase tracking-wider">
                  <th className="text-left px-4 py-3 font-medium">Хэрэглэгч</th>
                  <th className="text-left px-4 py-3 font-medium">Имэйл</th>
                  <th className="text-center px-4 py-3 font-medium">Дүр</th>
                  <th className="text-center px-4 py-3 font-medium">Статус</th>
                  <th className="text-left px-4 py-3 font-medium">Бүртгэсэн</th>
                  <th className="w-16" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((u) => (
                  <tr
                    key={u.id}
                    className="border-b border-border/50 last:border-0 hover:bg-muted/20 transition-colors"
                  >
                    {/* Name */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-950/50 flex items-center justify-center shrink-0">
                          <span className="text-xs font-bold text-blue-600 dark:text-blue-400">
                            {u.full_name.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <span className="font-semibold text-foreground">
                          {u.full_name}
                        </span>
                      </div>
                    </td>

                    {/* Email */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 text-muted-foreground text-xs">
                        <Mail className="w-3.5 h-3.5 shrink-0" />
                        {u.email}
                      </div>
                    </td>

                    {/* Role */}
                    <td className="px-4 py-3 text-center">
                      <Badge
                        className={`text-xs border ${ROLE_STYLE[u.role_id] ?? "bg-muted text-muted-foreground"}`}
                      >
                        {ROLE_LABELS[u.role_id] ?? `Дүр ${u.role_id}`}
                      </Badge>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3 text-center">
                      <Badge
                        className={`text-xs border ${STATUS_STYLE[u.status] ?? "bg-muted text-muted-foreground"}`}
                      >
                        {STATUS_LABELS[u.status] ?? u.status}
                      </Badge>
                    </td>

                    {/* Created */}
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {u.created_at
                        ? new Date(u.created_at).toLocaleDateString("mn-MN")
                        : "—"}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 justify-end">
                        <button
                          onClick={() => openEdit(u)}
                          className="p-1.5 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                          title="Засах"
                        >
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleDelete(u)}
                          className="p-1.5 rounded hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors text-muted-foreground hover:text-red-600"
                          title="Устгах"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Add / Edit dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {editingUser ? "Хэрэглэгч засах" : "Шинэ хэрэглэгч нэмэх"}
            </DialogTitle>
            <DialogDescription className="sr-only">
              Хэрэглэгчийн нэр, имэйл, нууц үг, дүр болон төлвийг удирдана.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-4 pt-2">
            <div>
              <Label htmlFor="full_name" className="mb-1.5 block">
                Бүтэн нэр <span className="text-red-500">*</span>
              </Label>
              <Input
                id="full_name"
                value={formData.full_name}
                onChange={(e) =>
                  setFormData((p) => ({ ...p, full_name: e.target.value }))
                }
                placeholder="Батболд Дорж"
                required
              />
            </div>

            <div>
              <Label htmlFor="email" className="mb-1.5 block">
                Имэйл <span className="text-red-500">*</span>
              </Label>
              <Input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) =>
                  setFormData((p) => ({ ...p, email: e.target.value }))
                }
                placeholder="batbold@company.mn"
                required
                disabled={!!editingUser}
              />
              {editingUser && (
                <p className="text-xs text-muted-foreground mt-1">
                  Имэйл өөрчлөх боломжгүй
                </p>
              )}
            </div>

            <div>
              <Label htmlFor="password" className="mb-1.5 block">
                Нууц үг{" "}
                {editingUser ? (
                  "(хоосон орхивол өөрчлөгдөхгүй)"
                ) : (
                  <span className="text-red-500">*</span>
                )}
              </Label>
              <Input
                id="password"
                type="password"
                value={formData.password}
                onChange={(e) =>
                  setFormData((p) => ({ ...p, password: e.target.value }))
                }
                placeholder="••••••••"
                required={!editingUser}
                minLength={editingUser ? 0 : 6}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label htmlFor="role_id" className="mb-1.5 block">
                  Дүр
                </Label>
                <select
                  id="role_id"
                  value={formData.role_id}
                  onChange={(e) =>
                    setFormData((p) => ({
                      ...p,
                      role_id: Number(e.target.value),
                    }))
                  }
                  className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value={3}>Хэрэглэгч</option>
                  <option value={2}>Удирдлага</option>
                  <option value={1}>Админ</option>
                </select>
              </div>

              <div>
                <Label htmlFor="status" className="mb-1.5 block">
                  Статус
                </Label>
                <select
                  id="status"
                  value={formData.status}
                  onChange={(e) =>
                    setFormData((p) => ({ ...p, status: e.target.value }))
                  }
                  className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="active">Идэвхтэй</option>
                  <option value="inactive">Идэвхгүй</option>
                  <option value="suspended">Түдгэлзүүлсэн</option>
                </select>
              </div>
            </div>

            {formError && (
              <p className="rounded-md border border-red-200 bg-red-50 dark:bg-red-950/30 dark:border-red-900 px-3 py-2 text-sm text-red-700 dark:text-red-400">
                {formError}
              </p>
            )}

            <DialogFooter className="pt-2 gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setDialogOpen(false)}
              >
                Болих
              </Button>
              <Button
                type="submit"
                disabled={saving}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {saving
                  ? "Хадгалж байна..."
                  : editingUser
                    ? "Өөрчлөлт хадгалах"
                    : "Хэрэглэгч нэмэх"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
