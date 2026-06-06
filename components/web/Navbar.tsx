"use client";

import { useAuth } from "@/app/context/AuthContext";
import { LogOut, User } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { memo, useCallback } from "react";
import { buttonVariants } from "../ui/button";

function Navbar() {
  const { user, logout } = useAuth();
  const router = useRouter();

  const handleLogout = useCallback(() => {
    logout();
    router.replace("/auth/login");
  }, [logout, router]);

  return (
    <nav className="fixed top-0 left-0 right-0 z-[9999] w-full py-4 flex items-center justify-between app-page backdrop-blur-md border-b border-border">
      <div className="flex items-center gap-4 px-4">
        <Link href="/">
          <h1 className="text-2xl font-bold select-none ml-10 sm:ml-4">
            <span>Cyber</span>
            <span className="text-blue-500">Guard</span>
            <span className="text-blue-500">X</span>
          </h1>
        </Link>
      </div>

      <div className="flex items-center gap-2 sm:gap-4 mr-4 sm:mr-8">
        {user ? (
          // Show user menu when logged in
          <div className="flex items-center gap-2 sm:gap-3">
            <div className="flex items-center gap-2 px-2 sm:px-3 py-2 rounded-lg bg-muted text-foreground select-none">
              <User className="h-4 w-4 shrink-0" />
              <span className="text-sm font-medium hidden sm:block max-w-32 truncate">
                {user.name}
              </span>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 transition-colors select-none"
              title="Logout"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        ) : (
          // Show login/signup buttons when not logged in
          <>
            <Link
              className={`${buttonVariants()} text-white`}
              href="/auth/sign-up"
            >
              Бүртгүүлэх
            </Link>
            <Link
              className={`${buttonVariants({ variant: "outline" })}`}
              href="/auth/login"
            >
              Нэвтрэх
            </Link>
          </>
        )}
      </div>
    </nav>
  );
}

export default memo(Navbar);
