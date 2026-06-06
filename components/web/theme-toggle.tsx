"use client";

import { Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { memo, useCallback } from "react";

import { Button } from "@/components/ui/button";

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();

  const handleToggleTheme = useCallback(() => {
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
  }, [resolvedTheme, setTheme]);

  return (
    <Button variant="outline" size="icon" onClick={handleToggleTheme}>
      <Sun className="h-[1.2rem] w-[1.2rem] scale-100 rotate-0 transition-all in-[.dark]:scale-0 in-[.dark]:-rotate-90" />
      <Moon className="absolute h-[1.2rem] w-[1.2rem] scale-0 rotate-90 transition-all in-[.dark]:scale-100 in-[.dark]:rotate-0" />
      <span className="sr-only">Toggle theme</span>
    </Button>
  );
}

export default memo(ThemeToggle);
