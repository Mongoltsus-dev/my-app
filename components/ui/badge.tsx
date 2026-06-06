import * as React from "react"

import { cn } from "@/lib/utils"

function Badge({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium",
        className
      )}
      {...props}
    />
  )
}

export { Badge }
