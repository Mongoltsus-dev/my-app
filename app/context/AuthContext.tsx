"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";

interface RiskAssessment {
  loginRiskScore: number;
  loginRiskTier: "critical" | "high" | "medium" | "low";
  lastAssessment: string;
}

interface User {
  name: string;
  user_id: string;
  email: string;
  role: string;
  assignedAssets?: string[];
  riskAssessment?: RiskAssessment;
  riskScore?: number;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (user: User) => void;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function getStoredUser() {
  if (typeof window === "undefined") return null;

  const storedUser = localStorage.getItem("user");
  if (!storedUser) return null;

  try {
    return JSON.parse(storedUser) as User;
  } catch (error) {
    console.error("Failed to parse stored user:", error);
    return null;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    queueMicrotask(() => {
      if (cancelled) return;

      setUser(getStoredUser());
      setIsLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback((userData: User) => {
    setUser(userData);
    localStorage.setItem("user", JSON.stringify(userData));
  }, []);

  const logout = useCallback(() => {
    void fetch("/api/v1/auth/logout", {
      method: "POST",
      credentials: "include",
    }).catch(() => {});
    setUser(null);
    localStorage.removeItem("user");
    localStorage.removeItem("failedLoginAttempts");
    localStorage.removeItem("accountLockoutTime");
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        login,
        logout,
        isAuthenticated: !!user,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
