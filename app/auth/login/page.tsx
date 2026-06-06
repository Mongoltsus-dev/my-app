"use client";

import { useAuth } from "@/app/context/AuthContext";
import { loginSchema } from "@/app/schemas/auth";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

type LoginFormData = z.infer<typeof loginSchema>;

interface LoginRiskAssessment {
  riskScore: number;
  riskTier: "critical" | "high" | "medium" | "low";
  recommendation: string;
  factors: string[];
}

interface ApiErrorResponse {
  message?: string;
}

interface AuthUserPayload {
  user_id: string | number;
  name?: string;
  email: string;
  role: string | number;
  assignedAssets?: string[];
}

interface LoginApiResponse extends ApiErrorResponse {
  requiresMFA?: boolean;
  tempSessionToken?: string;
  user?: AuthUserPayload;
}

interface MfaApiResponse extends ApiErrorResponse {
  user?: AuthUserPayload;
}

async function parseJsonResponse<T>(
  response: Response,
): Promise<{ data: T | null; isJson: boolean }> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  const isJson = contentType.includes("application/json");

  if (!isJson) {
    return { data: null, isJson: false };
  }

  try {
    const data = (await response.json()) as T;
    return { data, isJson: true };
  } catch {
    return { data: null, isJson: true };
  }
}

export default function LoginPage() {
  const [serverError, setServerError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [accountLockedUntil, setAccountLockedUntil] = useState<number | null>(
    null,
  );
  const [riskWarning, setRiskWarning] = useState<LoginRiskAssessment | null>(
    null,
  );
  const [showMFA, setShowMFA] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [tempSessionToken, setTempSessionToken] = useState<string | null>(null);

  const { login, user, isLoading: isAuthLoading } = useAuth();
  const router = useRouter();

  const MAX_LOGIN_ATTEMPTS = 5;
  const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: "",
      password: "",
    },
  });

  useEffect(() => {
    if (!isAuthLoading && user) {
      router.replace("/");
    }
  }, [isAuthLoading, user, router]);

  // Load lockout state from localStorage
  useEffect(() => {
    const storedLockoutTime = localStorage.getItem("accountLockoutTime");
    if (storedLockoutTime) {
      const lockoutTime = parseInt(storedLockoutTime);
      if (lockoutTime > Date.now()) {
        setAccountLockedUntil(lockoutTime);
      } else {
        localStorage.removeItem("accountLockoutTime");
      }
    }

    const storedFailedAttempts = localStorage.getItem("failedLoginAttempts");
    if (storedFailedAttempts) {
      setFailedAttempts(parseInt(storedFailedAttempts));
    }
  }, []);

  const isAccountLocked = accountLockedUntil
    ? // eslint-disable-next-line react-hooks/purity
      accountLockedUntil > Date.now()
    : false;

  // DETECT LAYER: Log audit event
  async function logAuditEvent(eventData: {
    eventType: "LOGIN_ATTEMPT" | "LOGIN_FAILURE" | "LOGIN_SUCCESS";
    email: string;
    userAgent: string;
    riskScore?: number;
  }): Promise<void> {
    try {
      await fetch("/api/v1/audit/log-login-event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          timestamp: new Date().toISOString(),
          ...eventData,
        }),
      });
    } catch (error) {
      console.error("Failed to log audit event:", error);
    }
  }

  // DETECT LAYER: Calculate login risk score
  async function calculateLoginRiskScore(
    email: string,
  ): Promise<LoginRiskAssessment> {
    try {
      const response = await fetch("/api/v1/risk/calculate-login-risk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
        }),
      });

      if (!response.ok) {
        return {
          riskScore: 0,
          riskTier: "low",
          recommendation: "",
          factors: [],
        };
      }

      const { data } = await parseJsonResponse<LoginRiskAssessment>(response);
      if (!data) {
        return {
          riskScore: 0,
          riskTier: "low",
          recommendation: "",
          factors: [],
        };
      }

      return data;
    } catch (error) {
      console.error("Failed to calculate risk score:", error);
      return {
        riskScore: 0,
        riskTier: "low",
        recommendation: "",
        factors: [],
      };
    }
  }

  async function onSubmit(values: LoginFormData) {
    setServerError("");
    setIsLoading(true);
    setRiskWarning(null);

    try {
      // PROTECT LAYER: Check account lockout
      if (isAccountLocked) {
        const remainingTime = Math.ceil(
          // eslint-disable-next-line react-hooks/purity
          ((accountLockedUntil || 0) - Date.now()) / 1000 / 60,
        );
        setServerError(
          `Бүртгэл түр хаагдсан байна. ${remainingTime} минутын дараа дахин оролдоно уу.`,
        );
        setIsLoading(false);
        return;
      }

      const userAgent = navigator.userAgent;

      // DETECT LAYER: Calculate login risk score
      const riskAssessment = await calculateLoginRiskScore(values.email);

      // Display risk warning
      if (riskAssessment.riskScore >= 25) {
        setRiskWarning(riskAssessment);
      }

      // DETECT LAYER: Log login attempt
      await logAuditEvent({
        eventType: "LOGIN_ATTEMPT",
        email: values.email,
        userAgent,
        riskScore: riskAssessment.riskScore,
      });

      // Attempt login
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: values.email,
          password: values.password,
          riskAssessment,
          userAgent,
        }),
      });

      const { data, isJson } = await parseJsonResponse<LoginApiResponse>(res);

      if (!data) {
        setServerError(
          isJson
            ? "Нэвтрэх үйлчилгээний JSON хариу буруу байна"
            : "Нэвтрэх үйлчилгээ санаандгүй хариу буцаалаа",
        );
        setIsLoading(false);
        return;
      }

      if (!res.ok) {
        // PROTECT LAYER: Handle failed attempts
        const newFailedAttempts = failedAttempts + 1;
        setFailedAttempts(newFailedAttempts);
        localStorage.setItem(
          "failedLoginAttempts",
          newFailedAttempts.toString(),
        );

        if (newFailedAttempts >= MAX_LOGIN_ATTEMPTS) {
          // eslint-disable-next-line react-hooks/purity
          const lockoutTime = Date.now() + LOCKOUT_DURATION_MS;
          setAccountLockedUntil(lockoutTime);
          localStorage.setItem("accountLockoutTime", lockoutTime.toString());

          await logAuditEvent({
            eventType: "LOGIN_FAILURE",
            email: values.email,
            userAgent,
            riskScore: riskAssessment.riskScore,
          });

          setServerError(
            "Хэт олон удаа буруу оролдсон тул бүртгэл 15 минут хаагдлаа.",
          );
        } else {
          setServerError(
            (data as ApiErrorResponse).message ||
              `Нэвтрэлт амжилтгүй (${newFailedAttempts}/${MAX_LOGIN_ATTEMPTS})`,
          );
        }

        setIsLoading(false);
        return;
      }

      // Check if MFA is required
      if (data.requiresMFA) {
        setTempSessionToken(data.tempSessionToken ?? null);
        setShowMFA(true);
        setIsLoading(false);
        return;
      }

      if (!data.user) {
        setServerError("Нэвтрэх хэрэглэгчийн мэдээлэл ирсэнгүй");
        setIsLoading(false);
        return;
      }

      // Successful login
      setFailedAttempts(0);
      setAccountLockedUntil(null);
      localStorage.removeItem("failedLoginAttempts");
      localStorage.removeItem("accountLockoutTime");

      await logAuditEvent({
        eventType: "LOGIN_SUCCESS",
        email: values.email,
        userAgent,
        riskScore: riskAssessment.riskScore,
      });

      // GOVERN LAYER: Store user with risk assessment
      login({
        user_id: String(data.user.user_id),
        name: data.user.name ?? data.user.email,
        email: data.user.email,
        role: String(data.user.role),
        riskAssessment: {
          loginRiskScore: riskAssessment.riskScore,
          loginRiskTier: riskAssessment.riskTier,
          lastAssessment: new Date().toISOString(),
        },
      });

      router.push("/");
    } catch (error) {
      console.error(error);
      setServerError("Сервертэй холбогдож чадсангүй");
      setIsLoading(false);
    }
  }

  async function handleMFASubmit(e: React.FormEvent) {
    e.preventDefault();
    setIsLoading(true);
    setServerError("");

    try {
      const response = await fetch("/api/v1/auth/verify-mfa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tempSessionToken,
          mfaCode,
        }),
      });

      const { data, isJson } =
        await parseJsonResponse<MfaApiResponse>(response);

      if (!data) {
        setServerError(
          isJson
            ? "MFA баталгаажуулалтын JSON хариу буруу байна"
            : "MFA баталгаажуулалт санаандгүй хариу буцаалаа",
        );
        setIsLoading(false);
        return;
      }

      if (!response.ok) {
        setServerError(
          (data as ApiErrorResponse).message || "MFA код буруу байна",
        );
        setIsLoading(false);
        return;
      }

      setShowMFA(false);
      setMfaCode("");
      setTempSessionToken(null);

      if (!data.user) {
        setServerError("MFA хэрэглэгчийн мэдээлэл ирсэнгүй");
        setIsLoading(false);
        return;
      }

      login({
        user_id: String(data.user.user_id),
        name: data.user.name ?? data.user.email,
        email: data.user.email,
        role: String(data.user.role),
        assignedAssets: data.user.assignedAssets,
      });
      router.push("/");
    } catch (error) {
      console.error("MFA verification error:", error);
      setServerError("MFA код шалгаж чадсангүй");
      setIsLoading(false);
    }
  }

  if (showMFA) {
    return (
      <Card className="max-w-md mx-auto">
        <CardHeader>
          <CardTitle>Олон хүчин зүйлийн баталгаажуулалт</CardTitle>
          <CardDescription>
            Баталгаажуулах кодыг таны и-мэйлд илгээлээ
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleMFASubmit}>
            <FieldGroup className="gap-y-4">
              <Field>
                <FieldLabel>Баталгаажуулах код</FieldLabel>
                <Input
                  placeholder="000000"
                  type="text"
                  value={mfaCode}
                  onChange={(e) =>
                    setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                  }
                  maxLength={6}
                  disabled={isLoading}
                  className="text-center text-2xl tracking-widest"
                />
              </Field>

              {serverError && (
                <div className="rounded-md bg-red-50 p-3 text-sm text-red-700">
                  {serverError}
                </div>
              )}

              <Button
                type="submit"
                disabled={isLoading || mfaCode.length !== 6}
                className="w-full"
              >
                {isLoading ? "Шалгаж байна..." : "Кодыг шалгах"}
              </Button>

              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setShowMFA(false);
                  setMfaCode("");
                  setTempSessionToken(null);
                }}
                className="w-full"
              >
                Нэвтрэх рүү буцах
              </Button>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="max-w-md mx-auto">
      <CardHeader>
        <CardTitle>Нэвтрэх</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={form.handleSubmit(onSubmit)}>
          <FieldGroup className="gap-y-4">
            <Controller
              name="email"
              control={form.control}
              render={({ field, fieldState }) => (
                <Field>
                  <FieldLabel>И-мэйл</FieldLabel>
                  <Input
                    aria-invalid={fieldState.invalid}
                    placeholder="johndoe@example.com"
                    type="email"
                    disabled={isAccountLocked || isLoading}
                    {...field}
                  />
                  {fieldState.invalid && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </Field>
              )}
            />

            <Controller
              name="password"
              control={form.control}
              render={({ field, fieldState }) => (
                <Field>
                  <FieldLabel>Нууц үг</FieldLabel>
                  <Input
                    aria-invalid={fieldState.invalid}
                    placeholder="••••••••"
                    type="password"
                    disabled={isAccountLocked || isLoading}
                    {...field}
                  />
                  {fieldState.invalid && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </Field>
              )}
            />
            {riskWarning && riskWarning.riskScore >= 25 && (
              <div
                className={`rounded-md border p-3 text-sm ${
                  riskWarning.riskScore >= 75
                    ? "border-red-300 bg-red-50 text-red-800"
                    : riskWarning.riskScore >= 50
                      ? "border-orange-300 bg-orange-50 text-orange-800"
                      : "border-yellow-300 bg-yellow-50 text-yellow-800"
                }`}
              >
                <p className="font-semibold">
                  ⚠️ Нэвтрэлтийн эрсдэл: {riskWarning.riskTier.toUpperCase()}
                </p>
                <p className="text-xs mt-1">{riskWarning.recommendation}</p>
                {riskWarning.factors.length > 0 && (
                  <p className="text-xs mt-2">
                    Хүчин зүйл: {riskWarning.factors.join(", ")}
                  </p>
                )}
              </div>
            )}

            {serverError && (
              <div className="rounded-md bg-red-50 p-3 text-sm text-red-700">
                ❌ {serverError}
              </div>
            )}

            <Button
              type="submit"
              disabled={isLoading || isAccountLocked}
              className="w-full"
            >
              {isLoading ? "Баталгаажуулж байна..." : "Нэвтрэх"}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  );
}
