"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  FileText,
  RefreshCw,
  Settings,
  Zap,
} from "lucide-react";

const actions = [
  {
    icon: <RefreshCw className="h-5 w-5" />,
    label: "Run New Scan",
    description: "Initiate a comprehensive security scan",
  },
  {
    icon: <FileText className="h-5 w-5" />,
    label: "Generate Report",
    description: "Create an executive summary report",
  },
  {
    icon: <Zap className="h-5 w-5" />,
    label: "View All Issues",
    description: "Open detailed findings dashboard",
  },
  {
    icon: <Settings className="h-5 w-5" />,
    label: "Configure Scan",
    description: "Customize scan parameters",
  },
];

export function QuickActions() {
  return (
    <Card>
      <CardHeader className="pb-4">
        <CardTitle className="text-base">Quick Actions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {actions.map((action, idx) => (
            <Button
              key={idx}
              variant="outline"
              className="h-auto flex flex-col items-start gap-2 p-4 hover:bg-muted"
            >
              <div className="flex items-center gap-2 w-full">
                <div className="text-muted-foreground">{action.icon}</div>
                <span className="font-medium text-sm">{action.label}</span>
              </div>
              <span className="text-xs text-muted-foreground text-left">
                {action.description}
              </span>
            </Button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
