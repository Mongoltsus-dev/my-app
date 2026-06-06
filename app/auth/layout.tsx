import { buttonVariants } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="absolute top-5 left-4 sm:left-5">
        <Link href="/" className={buttonVariants({ variant: "secondary" })}>
          <ArrowLeft className="size-4" />
          <span className="hidden sm:inline">Буцах</span>
        </Link>
      </div>
      <div className="absolute top-5 right-4 sm:right-5 flex items-center gap-2">
        <Link
          href="/auth/login"
          className={buttonVariants({ variant: "outline" })}
        >
          Нэвтрэх
        </Link>
      </div>
      <div className="w-full max-w-md mx-auto mt-16 sm:mt-0">{children}</div>
    </div>
  );
}
