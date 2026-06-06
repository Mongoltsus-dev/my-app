"use client";

import { useAuth } from "@/app/context/AuthContext";
import {
  BarChart3,
  BookOpen,
  Building2,
  ChevronLeft,
  ChevronRight,
  ClipboardList,
  Home,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Users,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ComponentType } from "react";
import { memo, useCallback, useMemo, useState } from "react";

interface MenuItem {
  label: string;
  href: string;
  icon: ComponentType<{ className?: string }>;
  category: string;
  adminOnly?: boolean;
}

const menuItems: MenuItem[] = [
  {
    label: "Эхлэх",
    href: "/",
    icon: Home,
    category: "",
  },
  {
    label: "Профайл",
    href: "/profile",
    icon: Building2,
    category: "Тохиргоо",
  },
  {
    label: "Хэрэглэгчид",
    href: "/users",
    icon: Users,
    category: "Тохиргоо",
    adminOnly: true,
  },
  {
    label: "Хамрах хүрээ",
    href: "/csf-scope",
    icon: ClipboardList,
    category: "Тохиргоо",
  },
  {
    label: "Хөрөнгүүд",
    href: "/assets",
    icon: Shield,
    category: "Удирдлага",
  },
  {
    label: "Аюулууд",
    href: "/threats",
    icon: ShieldAlert,
    category: "Удирдлага",
  },
  {
    label: "Дүрэм журам",
    href: "/policies",
    icon: BookOpen,
    category: "Удирдлага",
  },
  {
    label: "Эрсдэлийн үнэлгээ",
    href: "/assessments",
    icon: TriangleAlert,
    category: "Эрсдэлийн үнэлгээ",
  },
  {
    label: "Эрсдэлийн удирдлага",
    href: "/risks",
    icon: ShieldCheck,
    category: "Эрсдэлийн үнэлгээ",
  },
  {
    label: "Зөрүүгийн шинжилгээ",
    href: "/gap-analysis",
    icon: ClipboardList,
    category: "Эрсдэлийн үнэлгээ",
  },
  {
    label: "Тайлан",
    href: "/reports/risk-treatment",
    icon: BarChart3,
    category: "Тайлан",
  },
];

function Sidebar() {
  const [isOpen, setIsOpen] = useState(true);
  const pathname = usePathname();
  const { user } = useAuth();
  const isAdmin = Number(user?.role) === 1;

  const visibleItems = useMemo(
    () => menuItems.filter((item) => !item.adminOnly || isAdmin),
    [isAdmin],
  );

  // Group items by category (desktop only)
  const groupedItems = useMemo(
    () =>
      visibleItems.reduce(
        (acc, item) => {
          const existing = acc.find((g) => g.category === item.category);
          if (existing) {
            existing.items.push(item);
          } else {
            acc.push({ category: item.category, items: [item] });
          }
          return acc;
        },
        [] as Array<{
          category: MenuItem["category"];
          items: MenuItem[];
        }>,
      ),
    [visibleItems],
  );

  const isActive = useCallback((href: string) => pathname === href, [pathname]);

  const toggleSidebar = useCallback(() => {
    setIsOpen((prev) => !prev);
  }, []);

  return (
    <>
      {/* ── Mobile top nav (visible below md) ── */}
      <div className="md:hidden fixed left-0 right-0 top-16 z-9997 app-page border-b border-border">
        <nav
          className="flex items-center gap-1 overflow-x-auto px-3 py-2"
          aria-label="Primary"
        >
          {visibleItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`shrink-0 flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors ${
                  active
                    ? "bg-blue-100 dark:bg-blue-950 text-blue-600 dark:text-blue-400 font-semibold border-blue-200/80 dark:border-blue-900/70"
                    : "text-foreground border-transparent hover:bg-muted hover:border-border/70"
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="whitespace-nowrap">{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* ── Desktop sidebar (md and up) ── */}
      <aside
        className={`hidden md:block fixed left-0 top-0 h-screen app-page border-r border-border transition-[width] duration-200 ease-out will-change-[width] motion-reduce:transition-none z-9997 ${
          isOpen ? "w-64" : "w-20"
        }`}
      >
        <div className="flex flex-col h-full">
          {/* Logo Section */}
          <div className="p-4 border-b border-border">
            <Link href="/" className="flex items-center gap-2 select-none">
              <div className="p-2 rounded-lg bg-blue-600">
                <Shield className="w-5 h-5 text-white" />
              </div>
              {isOpen && (
                <div className="flex flex-col">
                  <span className="font-bold text-sm text-foreground">
                    Cyber
                  </span>
                  <span className="text-xs text-blue-600 -mt-1">GuardX</span>
                </div>
              )}
            </Link>
          </div>

          {/* Menu Items */}
          <nav className="flex-1 overflow-y-auto px-2 py-4 space-y-6">
            {groupedItems.map((group) => (
              <div key={group.category}>
                {isOpen && (
                  <p className="px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 select-none">
                    {group.category}
                  </p>
                )}
                <div className="space-y-2">
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const active = isActive(item.href);

                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        className={`group flex items-center rounded-xl border border-transparent transition-all duration-200 ease-out motion-reduce:transition-none select-none cursor-pointer active:scale-[0.98] active:shadow-inner focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
                          isOpen
                            ? "gap-3 px-3 py-2"
                            : "justify-center px-4 py-3"
                        } ${
                          active
                            ? "bg-blue-100 dark:bg-blue-950 text-blue-600 dark:text-blue-400 font-semibold border-blue-200/80 dark:border-blue-900/70 shadow-sm hover:shadow-md hover:-translate-y-0.5"
                            : "text-foreground hover:bg-muted hover:border-border/70 hover:shadow-sm hover:-translate-y-0.5"
                        }`}
                      >
                        <Icon className="w-5 h-5 shrink-0 transition-transform duration-200 ease-out group-hover:scale-110 group-active:scale-95" />
                        {isOpen && (
                          <span className="text-sm flex-1 truncate">
                            {item.label}
                          </span>
                        )}
                        {isOpen && active && (
                          <div className="w-2 h-2 rounded-full bg-blue-600 dark:bg-blue-400 transition-transform duration-200 group-hover:scale-125" />
                        )}
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>

          {/* Collapse Toggle */}
          <div className="border-t border-border p-3">
            <button
              onClick={toggleSidebar}
              className="group w-full flex items-center justify-center p-2 rounded-xl border border-border/60 bg-muted/30 hover:bg-muted/70 hover:border-border transition-all duration-200 hover:shadow-sm active:scale-95 text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              aria-label={isOpen ? "Collapse sidebar" : "Expand sidebar"}
            >
              {isOpen ? (
                <ChevronLeft className="w-5 h-5 transition-transform duration-200 group-hover:-translate-x-0.5" />
              ) : (
                <ChevronRight className="w-5 h-5 transition-transform duration-200 group-hover:translate-x-0.5" />
              )}
            </button>
          </div>
        </div>
      </aside>

      {/* Desktop spacer for content offset */}
      <div
        className={`hidden md:block transition-[width] duration-200 ease-out will-change-[width] motion-reduce:transition-none ${
          isOpen ? "w-64" : "w-20"
        }`}
      />
    </>
  );
}

export default memo(Sidebar);
